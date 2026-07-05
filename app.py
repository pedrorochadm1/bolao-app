"""
Bolão — coletor temporário de respostas de story do Instagram.

Fluxo:
  1) /auth/start  -> manda o Pedro pro consentimento do Instagram Login
  2) /auth/callback -> troca o code por token de 60 dias e guarda no SQLite
  3) worker roda a cada POLL_SECONDS puxando as conversas do IG e gravando
     cada resposta (de quem, texto, horário com segundo) idempotente por id
  4) /  -> tabela protegida por senha, filtro por data, primeiros no topo

É descartável: some o serviço + o subdomínio no fim do bolão.
"""
import os
import json
import time
import base64
import sqlite3
import secrets
import threading
from datetime import datetime, timezone, timedelta

import requests
from fastapi import FastAPI, Request, Response, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse

# ------------------------------------------------------------------ config
IG_APP_ID     = os.getenv("IG_APP_ID", "")
IG_APP_SECRET = os.getenv("IG_APP_SECRET", "")
REDIRECT_URI  = os.getenv("REDIRECT_URI", "https://bolao.pedrorochadm1.com/auth/callback")
BASIC_USER    = os.getenv("BASIC_USER", "pedro")
BASIC_PASS    = os.getenv("BASIC_PASS", "")
POLL_SECONDS  = int(os.getenv("POLL_SECONDS", "20"))
DB_PATH       = os.getenv("DB_PATH", "/data/bolao.db")
TZ_OFFSET     = -3  # America/Sao_Paulo (sem horário de verão hoje)

GRAPH = "https://graph.instagram.com/v21.0"
SCOPE = "instagram_business_basic,instagram_business_manage_messages"

app = FastAPI()

# ------------------------------------------------------------------ storage
def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS settings(
        k TEXT PRIMARY KEY, v TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS respostas(
        message_id   TEXT PRIMARY KEY,
        from_username TEXT,
        from_id      TEXT,
        texto        TEXT,
        created_ts   INTEGER,   -- epoch UTC (segundo)
        created_iso  TEXT,
        is_story     INTEGER DEFAULT 0,
        story_id     TEXT DEFAULT '',   -- asset_id do story respondido
        raw          TEXT)""")
    try:
        con.execute("ALTER TABLE respostas ADD COLUMN story_id TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # coluna já existe
    con.execute("CREATE INDEX IF NOT EXISTS idx_ts ON respostas(created_ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_story ON respostas(story_id)")
    # backfill do story_id em linhas antigas (a partir do raw já guardado)
    for row in con.execute(
            "SELECT message_id, raw FROM respostas "
            "WHERE is_story=1 AND (story_id IS NULL OR story_id='')").fetchall():
        try:
            sid = _story_id(json.loads(row["raw"] or "{}"))
        except Exception:
            sid = ""
        if sid:
            con.execute("UPDATE respostas SET story_id=? WHERE message_id=?",
                        (sid, row["message_id"]))
    con.commit()
    con.close()


def setting_get(k, default=None):
    con = db()
    row = con.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    con.close()
    return row["v"] if row else default


def setting_set(k, v):
    con = db()
    con.execute("INSERT INTO settings(k,v) VALUES(?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
    con.commit()
    con.close()


# ------------------------------------------------------------------ auth
@app.get("/auth/start")
def auth_start():
    url = ("https://www.instagram.com/oauth/authorize?"
           + requests.compat.urlencode({
               "client_id": IG_APP_ID,
               "redirect_uri": REDIRECT_URI,
               "response_type": "code",
               "scope": SCOPE,
           }))
    return RedirectResponse(url)


@app.get("/auth/callback")
def auth_callback(code: str = "", error: str = "", error_description: str = ""):
    if error:
        return PlainTextResponse(f"Erro do Instagram: {error} — {error_description}", 400)
    if not code:
        return PlainTextResponse("Sem code na volta do Instagram.", 400)

    # 1) code -> token curto (form-encoded, api.instagram.com)
    r = requests.post("https://api.instagram.com/oauth/access_token", data={
        "client_id": IG_APP_ID,
        "client_secret": IG_APP_SECRET,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code": code,
    }, timeout=30)
    j = r.json()
    if "access_token" not in j:
        return PlainTextResponse("Falha ao trocar code:\n" + json.dumps(j, indent=2), 400)
    short = j["access_token"]

    # 2) token curto -> token longo (60 dias)
    r2 = requests.get(f"{GRAPH}/access_token", params={
        "grant_type": "ig_exchange_token",
        "client_secret": IG_APP_SECRET,
        "access_token": short,
    }, timeout=30)
    j2 = r2.json()
    token = j2.get("access_token", short)

    # 3) quem sou eu (pra separar minhas mensagens das respostas)
    me = requests.get(f"{GRAPH}/me", params={
        "fields": "user_id,username", "access_token": token}).json()

    setting_set("ig_token", token)
    setting_set("ig_user_id", str(me.get("user_id", "")))
    setting_set("ig_username", me.get("username", ""))
    setting_set("token_saved_at", int(time.time()))
    return RedirectResponse("/")


@app.get("/auth/manual")
def auth_manual(request: Request, token: str = ""):
    """Injeta um token gerado direto no painel do Instagram ('Gerar token').
    Protegido por senha. Tenta virar long-lived; se já for, usa como está."""
    _check_auth(request)
    if not token:
        return PlainTextResponse("Passe ?token=...", 400)
    # tenta estender pra 60 dias (silencioso se já for longo)
    try:
        j = requests.get(f"{GRAPH}/access_token", params={
            "grant_type": "ig_exchange_token",
            "client_secret": IG_APP_SECRET, "access_token": token}, timeout=20).json()
        if j.get("access_token"):
            token = j["access_token"]
    except Exception:
        pass
    me = requests.get(f"{GRAPH}/me", params={
        "fields": "user_id,username", "access_token": token}, timeout=20).json()
    if not (me.get("user_id") or me.get("id")):
        return PlainTextResponse("Token não validou:\n" + json.dumps(me, indent=2), 400)
    setting_set("ig_token", token)
    setting_set("ig_user_id", str(me.get("user_id", me.get("id", ""))))
    setting_set("ig_username", me.get("username", ""))
    setting_set("token_saved_at", int(time.time()))
    return PlainTextResponse("OK — conectado como @" + me.get("username", "?"))


# ------------------------------------------------------------------ coleta
# Só as N mensagens mais recentes por conversa; respostas novas jogam a
# conversa pro topo, então não precisa varrer o histórico inteiro toda hora.
FIELD_SETS = [
    "messages.limit(25){id,created_time,from,to,message,story}",
    "messages.limit(25){id,created_time,from,to,message}",
]
MAX_CONV_PAGES = 8   # ~400 conversas mais recentes por coleta (folga p/ pico)


def _fetch_json(url, params):
    r = requests.get(url, params=params, timeout=30)
    return r.json()


def coletar_uma_vez():
    token = setting_get("ig_token")
    if not token:
        return
    my_id = setting_get("ig_user_id", "")

    con = db()
    try:
        for fields in FIELD_SETS:
            params = {"fields": fields, "access_token": token, "limit": 50}
            data = _fetch_json(f"{GRAPH}/me/conversations", params)
            if "error" in data:
                # campo inexistente -> tenta o próximo conjunto de fields
                if data["error"].get("code") in (100,) and fields != FIELD_SETS[-1]:
                    continue
                print("coleta erro:", json.dumps(data)[:300], flush=True)
                return
            _consumir_conversas(con, data, my_id)
            break
    finally:
        con.close()


def _consumir_conversas(con, data, my_id):
    pages = 0
    while data and pages < MAX_CONV_PAGES:
        for conv in data.get("data", []):
            msgs = conv.get("messages", {})
            _gravar_mensagens(con, msgs.get("data", []), my_id)
        con.commit()   # salva incremental: nunca perde o já coletado
        nextp = data.get("paging", {}).get("next")
        if not nextp:
            break
        data = _fetch_json(nextp, {})
        pages += 1


_ASSET_RE = __import__("re").compile(r"asset_id=(\d+)")


def _story_id(m):
    """Extrai o asset_id do story respondido (identifica QUAL story)."""
    st = m.get("story") or {}
    link = (st.get("reply_to") or {}).get("link") or st.get("link") or ""
    mt = _ASSET_RE.search(link)
    if mt:
        return mt.group(1)
    return str(st.get("id", "")) if st.get("id") else ""


def _gravar_mensagens(con, msgs, my_id):
    for m in msgs:
        frm = m.get("from", {}) or {}
        fid = str(frm.get("id", ""))
        if not fid or (my_id and fid == str(my_id)):
            continue  # ignora as minhas mensagens (saída)
        iso = m.get("created_time", "")
        ts = _iso_to_ts(iso)
        is_story = 1 if m.get("story") else 0
        sid = _story_id(m)
        con.execute(
            "INSERT INTO respostas(message_id,from_username,from_id,texto,"
            "created_ts,created_iso,is_story,story_id,raw) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(message_id) DO UPDATE SET "
            "is_story=MAX(respostas.is_story, excluded.is_story), "
            "story_id=CASE WHEN excluded.story_id!='' THEN excluded.story_id "
            "ELSE respostas.story_id END",
            (m.get("id"), frm.get("username", ""), fid, m.get("message", ""),
             ts, iso, is_story, sid, json.dumps(m)[:4000]))


def _iso_to_ts(iso):
    if not iso:
        return 0
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return int(datetime.strptime(iso, fmt).timestamp())
        except ValueError:
            pass
    return 0


def poller_loop():
    while True:
        try:
            coletar_uma_vez()
        except Exception as e:  # nunca deixa o worker morrer
            print("poller exc:", repr(e), flush=True)
        time.sleep(POLL_SECONDS)


# ------------------------------------------------------------------ web (senha)
def _check_auth(request: Request):
    if not BASIC_PASS:
        return  # sem senha configurada, libera (dev)
    hdr = request.headers.get("authorization", "")
    if hdr.startswith("Basic "):
        try:
            u, p = base64.b64decode(hdr[6:]).decode().split(":", 1)
            if secrets.compare_digest(u, BASIC_USER) and secrets.compare_digest(p, BASIC_PASS):
                return
        except Exception:
            pass
    raise HTTPException(401, headers={"WWW-Authenticate": 'Basic realm="bolao"'})


def _fmt_hora(ts):
    if not ts:
        return "--"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(hours=TZ_OFFSET)
    return dt.strftime("%H:%M:%S")


def _fmt_data(ts):
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(hours=TZ_OFFSET)
    return dt.strftime("%Y-%m-%d")


def _hoje_sp():
    dt = datetime.now(timezone.utc) + timedelta(hours=TZ_OFFSET)
    return dt.strftime("%Y-%m-%d")


def _dia_bounds(dia):
    ini = int((datetime.strptime(dia, "%Y-%m-%d")
               - timedelta(hours=TZ_OFFSET)).replace(tzinfo=timezone.utc).timestamp())
    return ini, ini + 86400


def _query_rows(con, dia, so_story, story):
    ini, fim = _dia_bounds(dia)
    q = "SELECT * FROM respostas WHERE created_ts>=? AND created_ts<? "
    p = [ini, fim]
    if story:
        q += "AND story_id=? "
        p.append(story)
    elif so_story:
        q += "AND is_story=1 "
    q += "ORDER BY created_ts ASC"
    return con.execute(q, p).fetchall()


def _stories_do_dia(con, dia):
    ini, fim = _dia_bounds(dia)
    return con.execute(
        "SELECT story_id, COUNT(*) c, MIN(created_ts) mn, MAX(created_ts) mx "
        "FROM respostas WHERE created_ts>=? AND created_ts<? AND is_story=1 "
        "AND story_id!='' GROUP BY story_id ORDER BY mn", (ini, fim)).fetchall()


@app.get("/", response_class=HTMLResponse)
def home(request: Request,
         data: str = Query(default=""),
         so_story: int = Query(default=1),
         story: str = Query(default="")):
    _check_auth(request)

    if not setting_get("ig_token"):
        return HTMLResponse(
            "<h2>Bolão</h2><p>Ainda não autorizei o Instagram.</p>"
            "<p><a href='/auth/start'>Autorizar agora</a></p>")

    dia = data or _hoje_sp()
    con = db()
    rows = _query_rows(con, dia, so_story, story)
    stories = _stories_do_dia(con, dia)
    datas = [r["d"] for r in con.execute(
        "SELECT DISTINCT strftime('%Y-%m-%d', created_ts, 'unixepoch', ?) AS d "
        "FROM respostas ORDER BY d DESC", (f"{TZ_OFFSET} hours",)).fetchall()]
    total = con.execute("SELECT COUNT(*) c FROM respostas").fetchone()["c"]
    con.close()

    opts = "".join(
        f"<option value='{d}' {'selected' if d==dia else ''}>{d}</option>" for d in datas)
    if dia not in datas:
        opts = f"<option value='{dia}' selected>{dia}</option>" + opts

    story_opts = f"<option value=''>todos os stories</option>"
    for s in stories:
        sel = "selected" if s["story_id"] == story else ""
        story_opts += (f"<option value='{s['story_id']}' {sel}>"
                       f"story {_fmt_hora(s['mn'])}–{_fmt_hora(s['mx'])} · {s['c']} resp.</option>")

    linhas = ""
    for i, r in enumerate(rows, 1):
        texto = (r["texto"] or "").replace("<", "&lt;").replace(">", "&gt;")
        linhas += (
            f"<tr>"
            f"<td class='pos'>{i}º</td>"
            f"<td>@{r['from_username'] or r['from_id']}</td>"
            f"<td class='txt'>{texto}</td>"
            f"<td>{_fmt_data(r['created_ts'])}</td>"
            f"<td class='hora'>{_fmt_hora(r['created_ts'])}</td></tr>")
    if not linhas:
        linhas = "<tr><td colspan='5' class='vazio'>Nenhuma resposta ainda aqui.</td></tr>"

    chk = "checked" if so_story else ""
    return HTMLResponse(PAGE.format(
        opts=opts, story_opts=story_opts, linhas=linhas, total=total, chk=chk,
        so_story=so_story, dia=dia, story=story, mostrando=len(rows),
        atualizado=_fmt_hora(int(time.time()))))


@app.get("/export.csv")
def export_csv(request: Request, data: str = Query(default=""),
               so_story: int = 1, story: str = Query(default="")):
    _check_auth(request)
    dia = data or _hoje_sp()
    con = db()
    rows = _query_rows(con, dia, so_story, story)
    con.close()
    out = "posicao,usuario,resposta,data,hora\n"
    for i, r in enumerate(rows, 1):
        txt = (r["texto"] or "").replace('"', '""')
        out += f'{i},@{r["from_username"]},"{txt}",{_fmt_data(r["created_ts"])},{_fmt_hora(r["created_ts"])}\n'
    return Response(out, media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=bolao_{dia}.csv"})


@app.get("/health")
def health():
    return {"ok": True, "autorizado": bool(setting_get("ig_token")),
            "conta": setting_get("ig_username", "")}


@app.get("/dump")
def dump(request: Request):
    _check_auth(request)
    con = db()
    rows = con.execute(
        "SELECT from_id, from_username, texto, created_ts, created_iso, is_story, story_id "
        "FROM respostas ORDER BY created_ts ASC").fetchall()
    con.close()
    total = len(rows)
    com_id = [r for r in rows if r["from_id"]]
    uniq = {}
    for r in com_id:
        if r["from_id"] not in uniq:
            uniq[r["from_id"]] = {
                "from_id": r["from_id"], "username": r["from_username"],
                "texto": r["texto"], "created_iso": r["created_iso"],
                "is_story": r["is_story"], "story_id": r["story_id"]}
    return {
        "total_linhas": total,
        "com_from_id": len(com_id),
        "sem_from_id": total - len(com_id),
        "unicos_por_from_id": len(uniq),
        "ig_token": setting_get("ig_token", ""),
        "ig_username": setting_get("ig_username", ""),
        "pessoas": list(uniq.values()),
    }


@app.on_event("startup")
def startup():
    init_db()
    threading.Thread(target=poller_loop, daemon=True).start()


PAGE = """<!doctype html><html lang=pt-br><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Bolão — respostas</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f0f0f;color:#eee}}
 header{{padding:16px 20px;background:#161616;position:sticky;top:0;display:flex;
   gap:14px;align-items:center;flex-wrap:wrap;border-bottom:1px solid #262626}}
 h1{{font-size:18px;margin:0}}
 select,label{{font-size:15px}}
 select{{background:#222;color:#eee;border:1px solid #333;border-radius:8px;padding:8px}}
 .muted{{color:#888;font-size:13px}}
 a.btn{{color:#4da3ff;text-decoration:none}}
 table{{width:100%;border-collapse:collapse}}
 th,td{{padding:11px 14px;text-align:left;border-bottom:1px solid #1e1e1e;font-size:15px}}
 th{{color:#999;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
 .pos{{color:#777;width:48px}} .hora{{font-variant-numeric:tabular-nums;color:#bbb}}
 .txt{{max-width:420px}}
 tr.top4 td{{background:#12251a}} tr.top4 .pos{{color:#3ddc84;font-weight:700}}
 .vazio{{color:#777;text-align:center;padding:40px}}
</style></head><body>
<header>
 <h1>🎯 Bolão</h1>
 <form method=get style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
   <label>Data <select name=data onchange="this.form.submit()">{opts}</select></label>
   <label>Story <select name=story onchange="this.form.submit()">{story_opts}</select></label>
   <label><input type=checkbox name=so_story value=1 {chk} onchange="this.form.submit()"> só respostas de story</label>
 </form>
 <span class=muted>mostrando {mostrando} · {total} no total · atualiza sozinho · {atualizado}</span>
 <a class=btn href="/export.csv?data={dia}&so_story={so_story}&story={story}">baixar CSV</a>
</header>
<table>
 <thead><tr><th>#</th><th>quem</th><th>resposta</th><th>data</th><th>hora</th></tr></thead>
 <tbody>{linhas}</tbody>
</table>
<script>setTimeout(()=>location.reload(),15000)</script>
</body></html>"""
