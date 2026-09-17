# Zenithal — How to Use & Demo It (PC · Mobile · Developer)

Zenithal is one detection "brain" (the backend) with several ways to use it.
Start the brain first, then pick the surface you want to demo.

```powershell
# Start the brain (backend) + dashboard
powershell -ExecutionPolicy Bypass -File run.ps1
# Backend  -> http://127.0.0.1:8000     Dashboard -> http://127.0.0.1:5173
```

Find your PC's LAN IP (for phone demos): run `ipconfig` and note the IPv4
address, e.g. `192.168.1.20`.

---

## 💻 On a PC (everyday user)

### A. SOC Dashboard (the monitoring screen)
Open `http://127.0.0.1:5173`. Five panels:
- **URL Scanner** — paste any link → verdict + IP intel + reasons.
- **Log Analyzer** — upload a server log → attacks + attacker IPs.
- **Attacker Map** — attackers plotted from real IP geolocation.
- **WhatsApp Guard** — paste a scam SMS/WhatsApp text → link auto-blocked.
- **Threat Feed** — every detection, live.

### B. Chrome extension (automatic, no pasting)
1. Chrome → `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select `zenithal/extension`.
3. Browse normally. Then:
   - **Right-click any link → "Scan link with Zenithal"** → notification with the verdict.
   - Click the toolbar icon → scans the current tab; type any URL to check it.
   - Risky-looking links get a ⚠️/⛔ badge inline as you browse.

**Demo line:** "It protects me *while I browse* — I never copy-paste anything."

---

## 📱 On a Mobile phone

### A. Install Zenithal as a phone app (PWA)
1. Make sure the phone is on the **same Wi-Fi** as the PC.
2. On the phone browser open `http://<PC-LAN-IP>:5173` (e.g. `http://192.168.1.20:5173`).
3. Chrome/Safari menu → **"Add to Home screen"** → Zenithal installs like an app
   (own icon, full-screen).
4. Open it → use **WhatsApp Guard**: paste a scam SMS like
   *"Your SBI account is blocked, verify: http://sbi-verify-now.top/login"* →
   it's flagged **MALICIOUS** and blocked before opening.

**Demo line:** "Here's the app on my phone — a scam SMS link gets blocked instantly."

### B. Device-wide protection with DNS (the production path)
For real automatic protection of *every* app on a phone (including WhatsApp),
Zenithal is designed to plug into a **DNS filter**: the phone's DNS points at
Zenithal, every domain a link tries to open is checked, and malicious ones are
blocked device-wide — no app needed. (This is how NextDNS / Pi-hole work; it's
the recommended production deployment for consumer phones. A native Android app
using a notification-listener to scan incoming SMS links is the alternative.)

---

## 🧑‍💻 As a Developer / Company

### A. Protect your web server in real time — WAF middleware
Blocks SQLi/XSS/traversal/command-injection **inline**, before they reach your
app. No log upload; decisions in microseconds.

```powershell
# run the example protected app (backend must be up on :8000)
cd zenithal
.venv\Scripts\python -m uvicorn integrations.example_protected_app:app --port 9000
```
```bash
curl "http://127.0.0.1:9000/products?id=5"                    # 200 OK
curl "http://127.0.0.1:9000/products?id=1' OR '1'='1"         # 403 BLOCKED (SQLi)
curl "http://127.0.0.1:9000/search?q=<script>alert(1)</script>"  # 403 BLOCKED (XSS)
```
Add it to *any* FastAPI/Starlette app in two lines:
```python
from integrations.waf_middleware import ZenithalWAF
app.add_middleware(ZenithalWAF, report_url="http://127.0.0.1:8000")
```
Every blocked attack also appears on the Zenithal dashboard map.

**Demo line:** "The attack is blocked *before* it hits my app — and I see the attacker on the map."

### B. Watch a live server log automatically — log agent
Instead of uploading a log, stream it live:
```powershell
.venv\Scripts\python integrations\log_agent.py C:\path\to\access.log --url http://127.0.0.1:8000
```
As new attack lines appear in the log, the dashboard lights up and (if configured)
you get a Slack/Telegram alert.

**Demo:** `python integrations/log_agent.py demo/live.log`, then append a line:
```
echo 198.51.100.77 - - [-] "GET /x?id=1 UNION SELECT pw FROM users HTTP/1.1" 500 0 "-" "-" >> demo/live.log
```
→ the agent reports the attack and the IP appears on the dashboard.

### C. Call the API from your own code
```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze/url \
     -H "Content-Type: application/json" \
     -d '{"url":"http://paypal-verify.tk/login"}'
```
```python
import httpx
r = httpx.post("http://127.0.0.1:8000/api/v1/analyze/url", json={"url": "..."})
print(r.json()["verdict"], r.json()["reasons"])
```
Batch up to 1000 URLs: `POST /api/v1/analyze/urls  {"urls": [...]}`.
Full interactive docs: `http://127.0.0.1:8000/docs`.

With auth on (`REQUIRE_API_KEY=true`), add header `-H "X-API-Key: <key>"`.

---

## One-line pitch per audience

| Audience | Surface | Pitch |
|---|---|---|
| **Everyday PC user** | Dashboard + Chrome extension | "Warns me before I click a bad link, automatically." |
| **Everyday phone user** | PWA app + DNS filter | "A scam SMS link is blocked before it opens." |
| **Developer / company** | WAF middleware + log agent + API | "Attacks are blocked in real time and mapped to the attacker's IP." |

See `docs/DEMO_SCRIPT.md` for the timed 3-minute pitch and `docs/PRODUCTION.md`
for turning on auth, alerts, Postgres/Redis, and scaling.
