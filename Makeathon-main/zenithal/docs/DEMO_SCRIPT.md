# Zenithal — 3-Minute Demo Script (SIH25229)

**Setup before judging:** run `run.ps1` (or start backend + `npm run dev`).
Keep the dashboard open on the **Threat Feed**. Backend on :8000, dashboard on :5173.
Everything works **offline** — no venue Wi-Fi needed.

---

### 0:00 — Hook (20s)
> "Over a billion phishing attacks hit users in 2023. But URLs don't just trick
> people — they also carry SQL-injection and XSS payloads that attack servers.
> Our problem statement asks us to identify **URL-based attacks from IP data**.
> Zenithal does exactly that — in one platform."

Point at the top **stats bar** (detections, malicious, attacker IPs, countries).

### 0:20 — Phishing URL (35s)
Open **URL Scanner** → click the `sbi-verify-now.top` sample.
> "Paste any link. Our XGBoost model plus IP intelligence returns a verdict —
> MALICIOUS, 95 out of 100 — and, crucially, **why**: brand impersonation, a
> high-abuse TLD, no HTTPS. A human analyst can trust this."

### 0:55 — WhatsApp guard (30s)
Open **WhatsApp Guard** → click the "URGENT: Your SBI account…" preset.
> "This is how users actually get attacked — over WhatsApp and SMS. Zenithal
> extracts the link, scans it, and **blocks it before it's opened.**"

### 1:25 — Server-side URL attacks (45s)  ← the PS clincher
Open **Log Analyzer** → upload `demo/sample_access.log`.
> "Now the other half of the problem. We feed in a web-server access log.
> Zenithal finds **18 URL-based attacks** across five techniques — SQL injection,
> XSS, traversal, command injection, LFI — and here's the key: it groups them
> **by attacker IP**. This IP, 45.135.232.17, is a bulletproof host in Russia
> running an automated SQL-injection scan."

Click the top attacker row to show the profile + reasons.

### 2:10 — Attacker map (25s)
Open **Attacker Map**.
> "Every attacker IP is geolocated from real IP data and plotted live. A SOC
> team sees the whole campaign — countries, ASNs, verdicts — at a glance."

### 2:35 — Close (25s)
> "Zenithal identifies URL-based attacks from IP data — exactly as SIH25229
> asks — for both phishing links and server exploits. It's explainable,
> real-time, runs offline, and scales to millions of URLs. Thank you."

(If asked about accuracy, be honest: bundled demo uses synthetic data; point the
training scripts at PhishTank/Tranco and CSIC-2010 for ~96–99% on real data.)

---

## Backup / FAQ answers
- **"Is the IP data real?"** GeoLite2 gives live geo/ASN when installed; otherwise
  a curated offline reference (real countries/ASNs for the demo IPs) so it works
  without internet. No fabricated geo is ever used to assert a mismatch.
- **"What about zero-day domains?"** Detection is structural (lexical + hosting),
  needing no blacklist — so brand-new domains are still caught.
- **"How does it scale?"** Stateless engines behind FastAPI; swap SQLite for
  Postgres/Redis; `docker compose up` brings the whole stack up.
