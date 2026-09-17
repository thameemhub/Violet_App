# Zenithal — Production Guide

Everything below is **opt-in**: with no configuration the app runs offline for
demos. Set environment variables to switch each capability on. Install the extra
libraries with `pip install -r requirements-prod.txt`.

---

## 1. Security

### API keys
```bash
REQUIRE_API_KEY=true
API_KEYS=key-for-alice,key-for-bob     # comma-separated
```
Clients send `X-API-Key: <key>` on `/analyze/*` and `/ip/*`. Read-only dashboard
endpoints stay open so the UI works. For the dashboard to send a key, build it
with `VITE_API_KEY=<key>`. (Verified: missing/invalid key → 401.)

### Rate limiting
```bash
RATE_LIMIT_MAX=120        # requests per window (0 disables)
RATE_LIMIT_WINDOW=60      # seconds
```
Per API-key when auth is on, else per client IP. In-process by default; use Redis
(below) to share limits across multiple workers/servers. (Verified: over-limit → 429.)

### HTTPS
Terminate TLS at a reverse proxy in front of the app — don't do it in Python.
Minimal Caddy example (auto HTTPS):
```
zenithal.example.com {
    reverse_proxy /api/*  backend:8000
    reverse_proxy         dashboard:80
}
```
Or use nginx with certbot / a cloud load balancer.

---

## 2. Reliability

### Postgres (instead of SQLite)
```bash
pip install asyncpg
DATABASE_URL=postgresql+asyncpg://user:pass@db-host:5432/zenithal
```
No code change — the app uses SQLAlchemy async; tables auto-create on startup.

### Redis cache + shared rate limiting
```bash
pip install redis
REDIS_URL=redis://redis-host:6379/0
CACHE_TTL=900
```
Repeated URL scans return instantly; falls back to an in-process cache if Redis
is unavailable (never errors). `/health` shows `cache: redis` when active.

### Error monitoring
```bash
pip install sentry-sdk
SENTRY_DSN=https://...ingest.sentry.io/...
```
Unhandled errors are logged and reported; clients only ever get a generic 500
(no stack traces leak).

---

## 3. Freshness — auto-updating threat feeds

Detection is backed by three live phishing/malware feeds (all free, no key):
**URLhaus** (malware) + **OpenPhish** (phishing) + **PhishTank** (verified
phishing) → merged into the blocklist (~30k malicious hosts). Optional API keys
raise rate limits:
```bash
PHISHTANK_API_KEY=...        # optional; higher PhishTank rate limit
OPENPHISH_FEED_URL=...       # optional; premium OpenPhish feed
```
Refresh manually:
```bash
python training/update_feeds.py            # feeds + reputation lists
python training/update_feeds.py --retrain  # + rebuild dataset, retrain, validate
```
Scheduled (already set up on this machine — Windows task **ZenithalFeedUpdate**,
daily 03:00, via `backend/scheduled_update.ps1`):
- **Windows:** `schtasks /Create /TN ZenithalFeedUpdate /TR "powershell -ExecutionPolicy Bypass -File <path>\backend\scheduled_update.ps1" /SC DAILY /ST 03:00 /F`
- **Linux/macOS (cron):** `0 3 * * * cd /app/backend && python training/update_feeds.py`
- Restart the backend (or schedule a restart after the update) so it loads the
  refreshed lists.

`update_feeds.py` runs `validate_url_model.py` after retraining and **fails loudly
if a new model would regress on common legit sites** — so a bad feed can't silently
break detection.

---

## 4. Automatic alerts (get notified, don't poll)

```bash
# Slack / generic webhook
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
# or Telegram
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=987654321
ALERT_MIN_VERDICT=MALICIOUS        # or SUSPICIOUS
```
Every qualifying detection pushes a message (verdict, target, source IP, reason)
in the background. `/health` shows `alerts: on`.

---

## 5. Scale — millions of URLs

Built in:
- **`POST /api/v1/analyze/urls`** — batch endpoint (up to 1000 URLs/call).
- Stateless engines + Redis cache/limits → **scale horizontally**.

Scale-out recipe:
1. Run several backend workers: `uvicorn app.main:app --workers 4` (or `gunicorn -k uvicorn.workers.UvicornWorker -w 4`).
2. Put them behind nginx / a load balancer.
3. Use Postgres + Redis so state is shared.
4. For very large asynchronous bulk jobs, push URLs onto a queue (Celery/RQ +
   Redis broker) and have workers call the same engine functions
   (`url_engine.analyze`) — the detection code is already queue-ready.

---

## 6. Deploy with Docker

```bash
docker compose up --build      # dashboard :8080, API :8000
```
Set the production env vars in `docker-compose.yml` under `backend.environment`,
and mount real datasets / GeoLite2 into the backend as already configured.

---

## Environment variable reference

| Variable | Default | Purpose |
|---|---|---|
| `REQUIRE_API_KEY` | `false` | Enforce `X-API-Key` on scan endpoints |
| `API_KEYS` | `zenithal-dev-key` | Accepted keys (comma-separated) |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | `120` / `60` | Requests per window |
| `DATABASE_URL` | SQLite file | Postgres DSN for production |
| `REDIS_URL` | _(empty)_ | Enable Redis cache/limits |
| `CACHE_TTL` | `900` | Cache lifetime (seconds) |
| `ALERT_WEBHOOK_URL` | _(empty)_ | Slack/generic alert webhook |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | _(empty)_ | Telegram alerts |
| `ALERT_MIN_VERDICT` | `MALICIOUS` | Minimum severity to alert |
| `SENTRY_DSN` | _(empty)_ | Error monitoring |
| `CORS_ORIGINS` | `*` | Allowed origins (comma-separated) |
| `ENABLE_ONLINE_ENRICHMENT` | `false` | Allow live WHOIS/reputation lookups |
