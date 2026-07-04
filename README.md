# bolao-app (temporário)

Coletor de respostas de story do Instagram pra ranquear os primeiros a responder.
Descartável: apagar o serviço no EasyPanel e o subdomínio no Cloudflare quando o bolão acabar.

## Env
- `IG_APP_ID`, `IG_APP_SECRET` — credenciais do Instagram Login
- `REDIRECT_URI` — https://bolao.pedrorochadm1.com/auth/callback
- `BASIC_USER`, `BASIC_PASS` — senha da página
- `POLL_SECONDS` — intervalo de coleta (default 20)
- `DB_PATH` — /data/bolao.db (volume)

## Autorizar
Abrir `/auth/start` uma vez → consentimento do Instagram → volta autenticado.
