<![CDATA[<div align="center">

# 🛡️ Zenithal — Identification of URL-Based Attacks from IP Data

### **Smart India Hackathon · SIH25229 · Theme: Cybersecurity · Team: The Zenithal**

> **One detection brain** that identifies phishing links *and* server-side injection attacks,
> fuses **IP intelligence** (geolocation, ASN, reputation, IP↔domain correlation) to score,
> explain, and map every threat in a real-time SOC dashboard — with a native Android app,
> Chrome extension, Telegram bot, and production-ready integrations.

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Dashboard-React%2018-61DAFB?logo=react)](https://react.dev/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost-FF6F00?logo=xgboost)](https://xgboost.readthedocs.io/)
[![Kotlin](https://img.shields.io/badge/Mobile-Kotlin%20Compose-7F52FF?logo=kotlin)](https://kotlinlang.org/)
[![Chrome](https://img.shields.io/badge/Extension-Chrome%20MV3-4285F4?logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/)
[![Docker](https://img.shields.io/badge/Deploy-Docker%20Compose-2496ED?logo=docker)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 📑 Table of Contents

1. [Problem Statement](#-problem-statement)
2. [Proposed Solution](#-proposed-solution)
3. [Why Zenithal Matches the Problem Statement](#-why-zenithal-matches-the-problem-statement)
4. [System Architecture](#-system-architecture)
5. [Data Flow](#-data-flow)
6. [Tech Stack](#-tech-stack)
7. [Repository Structure](#-repository-structure)
8. [Prerequisites](#-prerequisites)
9. [Clone & Setup (Step-by-Step)](#-clone--setup-step-by-step)
10. [Running on Mobile (Android App)](#-running-on-mobile-android-app)
11. [Running the PWA on a Phone](#-running-the-pwa-on-a-phone)
12. [Chrome Extension Setup](#-chrome-extension-setup)
13. [Telegram Bot Setup](#-telegram-bot-setup)
14. [API Reference](#-api-reference)
15. [Detection Engines — Deep Dive](#-detection-engines--deep-dive)
16. [Training Your Own Models](#-training-your-own-models)
17. [Production Deployment](#-production-deployment)
18. [Integrations (WAF, Log Agent)](#-integrations-waf-log-agent)
19. [3-Minute Demo Flow](#-3-minute-demo-flow)
20. [Measured Accuracy & Datasets](#-measured-accuracy--datasets)
21. [Environment Variables Reference](#-environment-variables-reference)
22. [Known Limitations & Roadmap](#-known-limitations--roadmap)
23. [Contributing](#-contributing)
24. [License](#-license)

---

## 🔴 Problem Statement

> **SIH25229 — "Identification of URL Based Attacks from IP Data"**
> Theme: Cybersecurity · Category: Software

The problem statement demands a system that:

1. **Identifies URL-based attacks** — not limited to phishing links, but the full spectrum: SQL injection, cross-site scripting (XSS), path traversal, command injection, and local/remote file inclusion (LFI/RFI) delivered through request URLs.
2. **Uses IP data** — geolocation, ASN (Autonomous System Number), reputation scores, reverse DNS, and IP-domain correlation — as a core signal for detection and attribution, not just decoration.
3. **Provides actionable intelligence** — human-readable explanations, attacker profiling, and a real-time monitoring interface for SOC (Security Operations Centre) teams.

### The Gap in Existing Solutions

| Existing Approach | Gap |
|---|---|
| VirusTotal / Google Safe Browsing | Only classify URLs — no IP attribution, no server-attack detection |
| Traditional WAFs (ModSecurity, AWS WAF) | Block attacks but don't attribute to IPs or explain *why* |
| SIEM platforms (Splunk, ELK) | Require expensive licensing, complex setup, and manual rule-writing |
| Phishing-only browser extensions | Only cover client-side links, miss server-side attacks entirely |

**No single open-source tool unifies phishing URL detection + server-side URL attack detection + IP intelligence + explainability + real-time dashboards.**

---

## 💡 Proposed Solution

**Zenithal** is an AI-powered, multi-surface URL threat intelligence platform that solves SIH25229 end-to-end:

```
┌────────────────────────────────────────────────────────────┐
│                   ZENITHAL PLATFORM                         │
│                                                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│   │ Dashboard │  │ Android  │  │ Chrome   │  │ Telegram │  │
│   │ (React)  │  │   App    │  │Extension │  │   Bot    │  │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│        │              │             │              │        │
│        └──────────────┴──────┬──────┴──────────────┘        │
│                              │                              │
│                    ┌─────────▼─────────┐                    │
│                    │  FastAPI Backend  │                    │
│                    │   /api/v1         │                    │
│                    ├───────────────────┤                    │
│                    │ Engine 1: Phishing│                    │
│                    │ Engine 2: Payload │                    │
│                    │ IP Intelligence  │                    │
│                    │ Explainability   │                    │
│                    │ Community Intel  │                    │
│                    └─────────┬────────┘                    │
│                              │                              │
│              ┌───────────────┼───────────────┐              │
│              │               │               │              │
│        ┌─────▼────┐   ┌─────▼────┐   ┌──────▼─────┐       │
│        │ SQLite/  │   │  Redis   │   │  MaxMind   │       │
│        │ Postgres │   │  Cache   │   │  GeoLite2  │       │
│        └──────────┘   └──────────┘   └────────────┘       │
└────────────────────────────────────────────────────────────┘
```

### Key Innovation: Omnichannel + IP-Centric Detection

1. **Two Detection Engines** — Engine 1 catches phishing/malicious URLs; Engine 2 catches SQLi/XSS/traversal in server logs. Both are fused with IP intelligence.
2. **IP Data as a First-Class Signal** — Every verdict is enriched with geolocation, ASN, hosting classification, reputation, reverse DNS, and brand-geo mismatch detection.
3. **Explainability** — Every verdict returns ranked, plain-language reasons ("IP-domain mismatch: 'sbi-verify.top' mimics a brand expected in IN, but is hosted in Russia").
4. **Five Access Surfaces** — SOC Dashboard, Android app (native Kotlin/Compose), Chrome extension, Telegram bot, and REST API.
5. **Works Offline** — Pre-trained models + bundled IP reference table means zero-setup demos with no internet.

---

## ✅ Why Zenithal Matches the Problem Statement

| PS Phrase | What Zenithal Delivers |
|---|---|
| **"URL Based Attacks"** | **Engine 1** detects phishing/malicious URLs (XGBoost + 38 features). **Engine 2** detects SQL injection, XSS, path traversal, command injection, LFI/RFI carried in request URLs via signatures + char n-gram TF-IDF ML. |
| **"from IP Data"** | Every verdict enriched with GeoIP, ASN/hosting org, reputation, reverse DNS, and **IP↔domain correlation** (brand-geo mismatch). Server attacks aggregated into ranked **attacker-IP profiles** plotted on a world map. |
| **"Identification"** | Not just detection — **explainability layer** produces ranked, human-readable reasons. Attacker profiles with volume, technique diversity, velocity, infra risk scores. |

> Full mapping: [`docs/PS_MAPPING.md`](docs/PS_MAPPING.md)

---

## 🏗️ System Architecture

```
                          ┌──────────────── React SOC Dashboard ───────────────┐
                          │ Feed · URL Scanner · Log Analyzer · Map · WA Guard  │
                          └───────────────▲───────────────────▲────────────────┘
                                    REST  │            WebSocket (live feed)
                          ┌───────────────┴───────────────────┴────────────────┐
                          │                 FastAPI  /api/v1                    │
                          ├──────────────────────────────────────────────────────┤
   URL / message ──────►  │ Engine 1: URL   → XGBoost(38 feats) + IP correlation │
   access log / PCAP ──►  │ Engine 2: Payload → signatures + char-TFIDF model    │
                          │ IP Intelligence  → GeoIP + ASN + reputation + rDNS   │
                          │ WHOIS Intel      → domain age + registrar + privacy  │
                          │ SSL Intel        → cert validity + issuer + SAN      │
                          │ Explainability   → plain-language reasons            │
                          │ Community Intel  → crowdsourced URL reports + votes  │
                          │ SQLite/Postgres  → detections + attacker_ips         │
                          └──────────────────────────────────────────────────────┘
                                ▲              ▲              ▲
                                │              │              │
                       ┌────────┘     ┌────────┘     ┌────────┘
                       │              │              │
              ┌────────┴───┐  ┌───────┴────┐  ┌─────┴──────┐
              │  Android   │  │  Chrome    │  │  Telegram  │
              │  Violet    │  │  MV3 Ext  │  │  Bot       │
              │  App       │  │           │  │            │
              └────────────┘  └───────────┘  └────────────┘
```

### Component Breakdown

| Component | Technology | Purpose |
|---|---|---|
| **Backend** | FastAPI (Python 3.11) | REST API, WebSocket feed, ML inference, IP intelligence, DB persistence |
| **Engine 1** | XGBoost + 38 URL features | Phishing/malicious URL detection with reputation-first architecture |
| **Engine 2** | Signatures + char n-gram TF-IDF | Server-side URL attack detection (SQLi, XSS, traversal, cmd injection, LFI/RFI) |
| **IP Intelligence** | MaxMind GeoLite2 / offline reference | Geolocation, ASN, reputation, reverse DNS, IP↔domain correlation |
| **WHOIS Intelligence** | python-whois | Domain age, registrar reputation, privacy detection |
| **SSL Intelligence** | Python ssl/socket | Certificate validity, issuer analysis, SAN checks |
| **Explainability** | Custom rule engine | Ranked plain-language reasons for every verdict |
| **Community Intel** | REST API + SQLite | Crowdsourced URL reports, voting, fused reputation |
| **SOC Dashboard** | React 18 + Vite + Tailwind | 5-panel SOC console (Feed, URL Scanner, Log Analyzer, Map, WhatsApp Guard) |
| **Android App** | Kotlin + Jetpack Compose | Native mobile app with notification listener, SMS scanning, overlay alerts |
| **Chrome Extension** | Manifest V3 | Scans links while browsing, right-click context menu, popup scanner |
| **Telegram Bot** | python-telegram-bot | Scan URLs sent via Telegram messages |
| **WAF Middleware** | FastAPI middleware | Drop-in inline WAF for any FastAPI/Starlette app |
| **Log Agent** | Python watchdog | Watches live server logs and streams attacks to dashboard |

---

## 🔄 Data Flow

```
Step 1: INPUT
   └── Client submits URL / email / text / access log / QR code
       via Dashboard, Android app, Chrome extension, Telegram bot, or API

Step 2: VALIDATION
   └── FastAPI validates and sanitizes input (Pydantic models)

Step 3: REPUTATION CHECK (Engine 1 — URL path)
   ├── Allowlist check → top-1M reputable domains (Majestic) → instant SAFE
   ├── Blocklist check → active threat feeds (URLhaus + OpenPhish + PhishTank) → instant MALICIOUS
   └── Neither → proceed to ML

Step 4: ML + HEURISTIC ANALYSIS
   ├── Engine 1 (URLs): 38 lexical/host features → XGBoost → risk score
   ├── Engine 2 (Logs): Parse Apache/Nginx log → signature layer → TF-IDF classifier
   ├── IP Intelligence: GeoIP + ASN + reputation + reverse DNS + IP↔domain correlation
   ├── WHOIS Intelligence: Domain age + registrar + privacy status
   └── SSL Intelligence: Certificate validity + issuer + SAN analysis

Step 5: SCORING & VERDICT
   └── Fused score (0-100) → SAFE / SUSPICIOUS / MALICIOUS
       with threat_type classification and confidence level

Step 6: EXPLAINABILITY
   └── Generate ranked, plain-language reasons
       (IP-data reasons prioritized per problem statement)

Step 7: PERSISTENCE
   └── Detection hashed and logged to DB with channel, threat_type,
       confidence, verdict, metadata, attacker profile

Step 8: REAL-TIME STREAMING
   └── Dashboard receives event over WebSocket (sub-second latency)

Step 9: ALERTING
   └── MALICIOUS detections trigger Slack/Telegram/webhook alerts

Step 10: FEEDBACK
   └── User feedback logged for model retraining + community reputation
```

---

## 🧰 Tech Stack

### Backend
| Technology | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Runtime |
| FastAPI | 0.115.0 | REST API + WebSocket framework |
| Pydantic | 2.9.2 | Request/response validation |
| SQLAlchemy (async) | 2.0.39 | ORM + async database |
| aiosqlite | 0.22.1 | Async SQLite driver (dev/demo) |
| asyncpg | — | Async PostgreSQL driver (production) |
| Redis | — | Cache + shared rate limiting (optional) |
| uvicorn | 0.30.6 | ASGI server |

### Machine Learning
| Technology | Purpose |
|---|---|
| XGBoost 3.2.0 | URL classifier (38 lexical/host features) |
| scikit-learn 1.6.1 | TF-IDF + classifier for payload detection |
| pandas 2.2.3 | Data processing for training |
| NumPy 2.1.3 | Numerical computations |
| joblib 1.4.2 | Model serialization |
| tldextract 5.1.2 | Domain/subdomain parsing |
| geoip2 4.8.0 | MaxMind GeoLite2 IP intelligence |
| python-whois 0.9.4 | WHOIS domain intelligence |

### SOC Dashboard
| Technology | Purpose |
|---|---|
| React 18.3 | UI framework |
| Vite 5.2 | Build tool + dev server |
| TailwindCSS 3.4 | Utility-first CSS |
| Recharts 2.12 | Charts and visualizations |
| React-Leaflet 4.2 | Interactive world map (attacker geo) |
| Lucide React | Icon library |
| Axios | HTTP client |

### Android App (VioletApp)
| Technology | Purpose |
|---|---|
| Kotlin | Language |
| Jetpack Compose (BOM 2025.05) | Declarative UI |
| Material 3 | Design system |
| Retrofit 2.11 + OkHttp 4.12 | API networking |
| Navigation Compose 2.9 | Screen navigation |
| DataStore Preferences | Local persistence |
| Coroutines 1.10 | Async operations |
| compileSdk 36, minSdk 26 | Android API targets |

### Chrome Extension
| Technology | Purpose |
|---|---|
| Manifest V3 | Extension platform |
| Vanilla JavaScript | Logic |
| chrome.storage | Local caching |
| contextMenus API | Right-click URL scanning |

### Infrastructure
| Technology | Purpose |
|---|---|
| Docker Compose | Container orchestration |
| Nginx | Reverse proxy (production) |
| PostgreSQL | Production database |
| Redis | Caching + rate limiting |

---

## 📁 Repository Structure

```
zenithal/
├── backend/                          # FastAPI Python backend
│   ├── app/
│   │   ├── main.py                   # FastAPI entrypoint + lifespan
│   │   ├── config.py                 # Central configuration (env-overridable)
│   │   ├── db.py                     # Async SQLAlchemy DB layer
│   │   ├── security.py              # API key auth + rate limiting
│   │   ├── cache.py                  # Redis / in-process cache
│   │   ├── alerts.py                 # Slack / Telegram / webhook alerts
│   │   ├── ws.py                     # WebSocket hub (live feed)
│   │   ├── api/
│   │   │   ├── routes.py            # Core API routes (/analyze/*, /dashboard/*)
│   │   │   └── community.py         # Community intelligence (/report, /vote)
│   │   ├── engines/
│   │   │   ├── url_engine.py         # Engine 1: Phishing URL detection
│   │   │   ├── payload_engine.py     # Engine 2: Server-side URL attacks
│   │   │   ├── ip_intel.py           # IP intelligence (geo, ASN, reputation)
│   │   │   ├── explain.py            # Explainability layer
│   │   │   ├── reputation.py         # Domain allowlist/blocklist
│   │   │   ├── whois_engine.py       # WHOIS domain intelligence
│   │   │   ├── ssl_engine.py         # SSL certificate intelligence
│   │   │   └── whois_constants.py    # Registrar reputation data
│   │   ├── ml/
│   │   │   ├── features_url.py       # 38-feature URL extractor
│   │   │   ├── features_payload.py   # Payload signature detection
│   │   │   ├── features_whois.py     # WHOIS feature extraction
│   │   │   ├── features_ssl.py       # SSL feature extraction
│   │   │   └── models/               # Trained model artifacts (.pkl)
│   │   └── bot/
│   │       ├── telegram_bot.py       # Telegram bot integration
│   │       └── explainability.py     # Bot-specific formatting
│   ├── training/
│   │   ├── train_url.py              # Train XGBoost URL classifier
│   │   ├── train_payload.py          # Train payload attack classifier
│   │   ├── build_url_dataset.py      # Build dataset from public feeds
│   │   ├── build_reputation.py       # Build domain allowlist/blocklist
│   │   ├── update_feeds.py           # Auto-update threat feeds
│   │   └── validate_url_model.py     # Model validation (acceptance tests)
│   ├── tests/                        # Unit tests
│   ├── data/                         # IP reference, GeoLite2 DBs, reputation lists
│   ├── requirements.txt              # Python dependencies
│   ├── requirements-prod.txt         # Production extras (Sentry, asyncpg, redis)
│   ├── Dockerfile                    # Backend container
│   └── zenithal.db                   # SQLite database (auto-created)
│
├── dashboard/                        # React SOC Dashboard
│   ├── src/
│   │   ├── App.jsx                   # Main shell (sidebar + stats bar + panels)
│   │   ├── main.jsx                  # React entry point
│   │   ├── index.css                 # Global styles
│   │   ├── panels/
│   │   │   ├── ThreatFeed.jsx        # Live detection feed
│   │   │   ├── UrlScanner.jsx        # Interactive URL scanner
│   │   │   ├── LogAnalyzer.jsx       # Access log upload + attack analysis
│   │   │   ├── AttackerMap.jsx       # World map with attacker IP pins
│   │   │   └── WhatsAppSim.jsx       # WhatsApp/SMS message scanner
│   │   ├── components/
│   │   │   └── Shared.jsx            # Reusable UI components
│   │   ├── context/
│   │   │   └── WebSocketContext.jsx   # Live WebSocket feed provider
│   │   └── services/
│   │       └── api.js                # Axios API client
│   ├── package.json                  # npm dependencies
│   ├── vite.config.js                # Vite configuration
│   ├── tailwind.config.js            # Tailwind configuration
│   ├── Dockerfile                    # Dashboard container (nginx)
│   └── nginx.conf                    # Nginx config (production)
│
├── VioletApp/                        # Native Android App (Kotlin + Compose)
│   ├── app/
│   │   ├── build.gradle.kts          # Android build config (compileSdk 36)
│   │   └── src/main/
│   │       ├── AndroidManifest.xml   # Permissions (Internet, SMS, overlay, notifications)
│   │       └── java/com/zenithal/violet/
│   │           ├── MainActivity.kt
│   │           ├── data/
│   │           │   ├── api/          # Retrofit client, API service, network utils
│   │           │   ├── local/        # History store, preferences manager
│   │           │   └── models/       # Data models
│   │           ├── service/
│   │           │   ├── VioletNotificationListener.kt   # Notification scanning
│   │           │   ├── SmsBroadcastReceiver.kt         # SMS interception
│   │           │   ├── OverlayService.kt               # Truecaller-style alert overlay
│   │           │   └── UrlExtractor.kt                 # URL extraction from text
│   │           └── ui/
│   │               ├── navigation/NavGraph.kt
│   │               ├── screens/
│   │               │   ├── SplashScreen.kt
│   │               │   ├── HomeScreen.kt               # Main scanner screen
│   │               │   ├── UrlResultScreen.kt          # Scan results display
│   │               │   ├── HistoryScreen.kt             # Scan history
│   │               │   ├── PermissionScreen.kt          # Permission setup guide
│   │               │   ├── MonitoredAppsScreen.kt       # App monitoring config
│   │               │   ├── MultiLinkScreen.kt           # Multi-URL scanning
│   │               │   ├── MessageDetailScreen.kt       # Message analysis
│   │               │   └── ReportVoteScreen.kt          # Community reporting
│   │               └── theme/                           # Material 3 theme
│   ├── build.gradle.kts              # Project-level Gradle
│   └── settings.gradle.kts
│
├── extension/                        # Chrome Browser Extension
│   ├── manifest.json                 # Manifest V3 config
│   ├── background.js                 # Service worker (context menu, notifications)
│   ├── content.js                    # Content script (inline link scanning)
│   ├── popup.html                    # Extension popup UI
│   └── popup.js                      # Popup logic
│
├── integrations/                     # Production integrations
│   ├── waf_middleware.py             # Drop-in WAF for FastAPI/Starlette apps
│   ├── log_agent.py                  # Live log watcher → dashboard streamer
│   └── example_protected_app.py      # Demo app protected by WAF
│
├── demo/                             # Demo assets
│   ├── sample_access.log            # Pre-built access log with attacks
│   ├── sample_phishing_urls.txt     # Sample phishing URLs for testing
│   └── live.log                     # Live log for agent demo
│
├── docs/                             # Documentation
│   ├── USAGE.md                      # How to use (PC, mobile, developer)
│   ├── PRODUCTION.md                 # Production deployment guide
│   ├── PS_MAPPING.md                 # Problem statement mapping
│   ├── DEMO_SCRIPT.md               # Timed 3-minute demo script
│   └── Zenithal_SIH25229.pptx       # Presentation deck
│
├── docker-compose.yml                # Full stack Docker deployment
├── run.ps1                           # One-command Windows dev launcher
└── .gitignore
```

---

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed:

| Requirement | Version | Why |
|---|---|---|
| **Python** | 3.11+ | Backend runtime |
| **pip** | Latest | Python package manager |
| **Node.js** | 18+ | Dashboard dev server |
| **npm** | 9+ | JavaScript package manager |
| **Git** | Any | Clone the repository |
| **Android Studio** | Latest (for mobile) | Build the VioletApp |
| **Docker + Docker Compose** | Latest (optional) | Containerized deployment |
| **Google Chrome** | Latest (for extension) | Chrome extension testing |

---

## 🚀 Clone & Setup (Step-by-Step)

### Step 1: Clone the Repository

```bash
git clone https://github.com/<your-org>/zenithal.git
cd zenithal
```

### Step 2: Set Up the Backend

```powershell
# Navigate to the backend directory
cd backend

# (Recommended) Create a Python virtual environment
python -m venv .venv

# Activate the virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Windows CMD:
.\.venv\Scripts\activate.bat
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Train the ML Models

```powershell
# Train the XGBoost URL classifier
# (uses synthetic data by default; supply real CSVs in training/data/ for higher accuracy)
python training/train_url.py

# Train the payload attack classifier
python training/train_payload.py
```

> **💡 Tip:** For production-grade accuracy, download real datasets first:
> - **Phishing URLs:** PhishTank / OpenPhish / URLhaus → `training/data/phishing_urls.csv`
> - **Benign URLs:** Tranco / Majestic top-list → `training/data/benign_urls.csv`
> - **URL attacks:** HTTP CSIC 2010 → `training/data/csic2010.csv`

### Step 4: (Optional) Set Up IP Geolocation

```powershell
# For real-time IP geolocation, download free MaxMind GeoLite2 databases:
# 1. Sign up at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# 2. Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
# 3. Place them in backend/data/

# Without these files, the bundled offline reference table is used automatically.
# The demo works perfectly offline — the map will never be empty.
```

### Step 5: (Optional) Set Up the `.env` File

Create a `.env` file in the project root for optional integrations:

```env
# Telegram Bot (optional)
TELEGRAM_HTTP_API=your-telegram-bot-token

# Online enrichment (optional — off by default for demo reliability)
ENABLE_ONLINE_ENRICHMENT=false

# API security (optional — off by default)
REQUIRE_API_KEY=false
API_KEYS=your-api-key-1,your-api-key-2
```

### Step 6: Start the Backend

```powershell
# From the backend/ directory
python -m uvicorn app.main:app --reload --port 8000

# ✅ API available at:     http://127.0.0.1:8000
# ✅ API docs at:          http://127.0.0.1:8000/docs
# ✅ Health check at:      http://127.0.0.1:8000/api/v1/health
```

### Step 7: Set Up the Dashboard

```powershell
# Open a NEW terminal, navigate to the dashboard
cd dashboard

# Install dependencies
npm install

# Start the development server
npm run dev

# ✅ Dashboard available at: http://127.0.0.1:5173
```

### Step 8: One-Command Launch (Windows)

Instead of Steps 6-7, you can launch everything with one command:

```powershell
# From the zenithal/ root directory
powershell -ExecutionPolicy Bypass -File run.ps1

# This opens:
#   Backend  → http://127.0.0.1:8000
#   Dashboard → http://127.0.0.1:5173
# And auto-opens the dashboard in your browser.
```

### Step 9: Docker Compose (Full Stack)

```bash
# From the zenithal/ root directory
docker compose up --build

# ✅ Dashboard: http://localhost:8080
# ✅ API:       http://localhost:8000
```

---

## 📱 Running on Mobile (Android App)

The **VioletApp** is a native Android app built with Kotlin and Jetpack Compose. It provides:

- **URL Scanner** — paste or type any URL for instant analysis
- **Notification Listener** — auto-scans URLs from WhatsApp, SMS, and other messaging app notifications
- **SMS Interception** — reads incoming SMS messages, extracts URLs, and scans them automatically
- **Overlay Alerts** — Truecaller-style pop-up overlay warning when a malicious link is detected
- **Scan History** — persistent history of all scanned URLs with verdicts
- **Community Reporting** — report and vote on suspicious URLs
- **Monitored Apps** — configure which apps to monitor for incoming links

### Step-by-Step: Build & Run the Android App

#### Step 1: Ensure the Backend is Running

The Android app connects to the Zenithal backend API. Make sure the backend is running on your PC:

```powershell
cd backend
python -m uvicorn app.main:app --port 8000
```

#### Step 2: Find Your PC's LAN IP Address

The phone needs to connect to the backend over your local Wi-Fi network:

```powershell
# Windows
ipconfig
# Look for "IPv4 Address" under your Wi-Fi adapter, e.g., 192.168.1.20

# macOS/Linux
ifconfig | grep "inet "
```

#### Step 3: Update the API Base URL

Edit `VioletApp/app/build.gradle.kts` and update the `API_BASE_URL` to your PC's LAN IP:

```kotlin
// Change this line:
buildConfigField("String", "API_BASE_URL", "\"http://127.0.0.1:8000/api/v1/\"")

// To your LAN IP:
buildConfigField("String", "API_BASE_URL", "\"http://192.168.1.20:8000/api/v1/\"")
```

> **⚠️ For Android emulator**, use `10.0.2.2` instead of `127.0.0.1`:
> ```kotlin
> buildConfigField("String", "API_BASE_URL", "\"http://10.0.2.2:8000/api/v1/\"")
> ```

#### Step 4: Open in Android Studio

1. Open **Android Studio**
2. Click **File → Open** → navigate to `zenithal/VioletApp/`
3. Wait for Gradle sync to complete (may take a few minutes on first open)
4. If prompted, install any required SDK versions (compileSdk 36)

#### Step 5: Build & Run

1. Connect your Android phone via USB (with **USB debugging** enabled) or start an emulator
2. Click the **▶ Run** button in Android Studio
3. Select your device/emulator
4. The app will build and install on your device

#### Step 6: Grant Permissions

On first launch, the app will guide you through necessary permissions:

| Permission | Purpose |
|---|---|
| **Internet** | API calls to the Zenithal backend |
| **Notification Access** | Scan URLs from WhatsApp/Telegram/SMS notifications |
| **SMS (Read/Receive)** | Intercept incoming SMS for URL scanning |
| **Display Over Other Apps** | Show Truecaller-style overlay alerts |

Navigate to **Settings → Permissions** in the app for a guided setup.

#### Step 7: Test It

1. Open the app → type or paste a URL (e.g., `http://sbi-verify-now.top/login`)
2. Tap **Scan** → see the verdict: **MALICIOUS** with reasons
3. Send yourself a WhatsApp message with a phishing link → the app intercepts and shows an overlay warning

### Architecture of the Mobile App

```
VioletApp/
├── MainActivity.kt ─────────────── Entry point (Compose navigation host)
│
├── data/
│   ├── api/
│   │   ├── ApiService.kt ────────── Retrofit API interface (/analyze/url, /community/*)
│   │   ├── RetrofitClient.kt ───── HTTP client with logging interceptor
│   │   ├── ConnectionMonitor.kt ── Real-time backend connectivity check
│   │   ├── NetworkResult.kt ────── Sealed class for API results
│   │   └── SafeApiCaller.kt ────── Error-handled API call wrapper
│   ├── local/
│   │   ├── HistoryStore.kt ─────── Persistent scan history (DataStore)
│   │   └── PreferencesManager.kt ─ App preferences & settings
│   └── models/
│       └── Models.kt ──────────── Data classes (ScanResult, etc.)
│
├── service/
│   ├── VioletNotificationListener.kt ── Listens to ALL notifications,
│   │                                     extracts URLs, scans via API
│   ├── SmsBroadcastReceiver.kt ──────── Intercepts incoming SMS,
│   │                                     extracts URLs, scans via API
│   ├── OverlayService.kt ───────────── Shows floating alert banner
│   │                                     over other apps (like Truecaller)
│   └── UrlExtractor.kt ─────────────── Regex-based URL extraction
│
└── ui/
    ├── navigation/NavGraph.kt ───── Compose navigation routes
    ├── screens/
    │   ├── SplashScreen.kt ──────── Animated splash
    │   ├── HomeScreen.kt ────────── URL input + quick stats + protection toggle
    │   ├── UrlResultScreen.kt ───── Detailed verdict + reasons + IP intel
    │   ├── HistoryScreen.kt ─────── List of past scans
    │   ├── PermissionScreen.kt ──── Guided permission setup
    │   ├── MonitoredAppsScreen.kt ─ Choose which apps to monitor
    │   ├── MultiLinkScreen.kt ───── Batch URL scanning
    │   ├── MessageDetailScreen.kt ─ Full message analysis
    │   └── ReportVoteScreen.kt ──── Community reporting UI
    └── theme/ ───────────────────── Material 3 colors, typography, shapes
```

---

## 🌐 Running the PWA on a Phone

If you prefer not to build the Android app, the dashboard is an **installable PWA** (Progressive Web App):

### Step 1: Ensure Backend + Dashboard Are Running on PC

```powershell
powershell -ExecutionPolicy Bypass -File run.ps1
```

### Step 2: Connect Phone to Same Wi-Fi

Ensure your phone and PC are on the **same Wi-Fi network**.

### Step 3: Open Dashboard on Phone

On your phone browser, navigate to:

```
http://<PC-LAN-IP>:5173
```

Example: `http://192.168.1.20:5173`

### Step 4: Install as App

- **Chrome (Android):** Menu (⋮) → **"Add to Home screen"** → **"Install"**
- **Safari (iOS):** Share button (⬆) → **"Add to Home Screen"**

### Step 5: Use It

The PWA installs with its own icon and runs full-screen like a native app. Use the **WhatsApp Guard** panel to paste scam messages and see URLs blocked instantly.

---

## 🔌 Chrome Extension Setup

### Step 1: Ensure Backend is Running

```powershell
cd backend && python -m uvicorn app.main:app --port 8000
```

### Step 2: Load the Extension

1. Open Chrome → navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right)
3. Click **"Load unpacked"**
4. Select the `zenithal/extension/` directory

### Step 3: Use It

- **Right-click any link** → select **"Scan link with Zenithal"** → notification with verdict
- **Click the toolbar icon** → type any URL → instant scan result
- **Browse normally** → risky links get a ⚠️ or ⛔ badge inline

> The extension communicates with the backend at `http://127.0.0.1:8000`. If running on a different host/port, update `manifest.json` → `host_permissions`.

---

## 🤖 Telegram Bot Setup

### Step 1: Create a Bot with BotFather

1. Open Telegram, search for **@BotFather**
2. Send `/newbot`, follow the prompts
3. Copy the **HTTP API token**

### Step 2: Configure the Token

Set the token in your `.env` file:

```env
TELEGRAM_HTTP_API=your-telegram-bot-token-here
```

### Step 3: Start the Backend

```powershell
cd backend
python -m uvicorn app.main:app --port 8000
```

The Telegram bot starts automatically with the backend (via the lifespan event). Send any URL to your bot on Telegram to get an instant threat analysis with verdict, score, reasons, IP intelligence, WHOIS data, and SSL certificate info.

### Bot Commands

| Command | Description |
|---|---|
| `/start` | Welcome message |
| `/help` | Usage instructions |
| *Send any message with a URL* | Automatic URL extraction + full analysis |

---

## 📡 API Reference

Base URL: `http://127.0.0.1:8000/api/v1`

Interactive docs: `http://127.0.0.1:8000/docs` (Swagger UI)

### Core Endpoints

| Method | Path | Description | Auth |
|---|---|---|---|
| `GET` | `/health` | System health + model status | — |
| `POST` | `/analyze/url` | Scan a single URL | Optional |
| `POST` | `/analyze/urls` | Batch scan (up to 1000 URLs) | Optional |
| `POST` | `/analyze/message` | Extract & scan URLs from text (WhatsApp/SMS) | Optional |
| `POST` | `/analyze/logfile` | Upload access log (multipart file) | Optional |
| `POST` | `/analyze/logtext` | Submit access log as text | Optional |
| `GET` | `/ip/{ip}` | Standalone IP intelligence lookup | Optional |

### Dashboard Endpoints (no auth)

| Method | Path | Description |
|---|---|---|
| `GET` | `/dashboard/stats` | Aggregated detection statistics |
| `GET` | `/dashboard/detections?limit=100` | Recent detections |
| `GET` | `/dashboard/attackers?limit=25` | Top attacker IP profiles |
| `WS` | `/ws/feed` | Live detection WebSocket stream |

### Community Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/community/report` | Submit a URL report |
| `GET` | `/community/reputation?url=...` | Query URL reputation (AI + community fused) |
| `POST` | `/community/vote-safe` | Upvote URL as safe |
| `POST` | `/community/vote-malicious` | Downvote URL as malicious |

### Example: Scan a URL

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze/url \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-verify.tk/login"}'
```

**Response:**

```json
{
  "input": "http://paypal-verify.tk/login",
  "verdict": "MALICIOUS",
  "score": 92.5,
  "threat_type": "phishing",
  "resolved_ip": "45.135.232.17",
  "ip_intel": {
    "country": "RU",
    "city": "Moscow",
    "asn": 204957,
    "org": "Chang Way Technologies",
    "hosting_type": "bulletproof",
    "reputation": "malicious"
  },
  "reasons": [
    "IP-domain mismatch: 'paypal-verify.tk' mimics PayPal (expected US), but is hosted in Russia (RU).",
    "Brand impersonation: URL contains 'paypal' — a commonly phished brand.",
    "High-risk TLD: .tk is heavily abused for phishing.",
    "No HTTPS: legitimate login pages use encrypted connections.",
    "Hosting network flagged malicious: Chang Way Technologies (bulletproof)."
  ],
  "whois": { "domain_age_days": 3, "registrar": "...", "privacy_enabled": true },
  "ssl": { "has_ssl": false },
  "id": 42,
  "created_at": "2026-09-17T04:19:31Z"
}
```

### Example: Scan a WhatsApp/SMS Message

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze/message \
     -H "Content-Type: application/json" \
     -d '{"text": "URGENT: Your SBI account is blocked! Verify now: http://sbi-verify-now.top/login", "sender": "+91-9876543210"}'
```

### Example: Upload Access Log

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze/logfile \
     -F "file=@demo/sample_access.log"
```

---

## 🔬 Detection Engines — Deep Dive

### Engine 1: Phishing URL Detection

**Architecture: Reputation First, ML for the Unknown**
(Same approach as Google Safe Browsing / Microsoft SmartScreen)

```
Input URL
   │
   ├── Step 1: Allowlist Check
   │   └── Registered domain in top-1M reputable sites (Majestic, minus shorteners)?
   │       ├── YES → SAFE (instant, no ML needed)
   │       └── NO → continue
   │
   ├── Step 2: Blocklist Check
   │   └── Host on active threat feed (URLhaus + OpenPhish + PhishTank)?
   │       ├── YES → MALICIOUS (instant, known bad)
   │       └── NO → continue
   │
   ├── Step 3: ML Classification (XGBoost)
   │   └── 38 lexical + host features → risk score (0-100)
   │       Features include:
   │       - URL length, path depth, query parameter count
   │       - Entropy of hostname, subdomain depth
   │       - TLD risk score, presence of IP-literal host
   │       - Brand keyword detection (paypal, sbi, etc.)
   │       - Shortener detection, encoded character ratio
   │       - Suspicious path keywords (/login, /verify, /update)
   │       - And 20+ more signals
   │
   ├── Step 4: IP Intelligence Fusion
   │   └── Resolve domain → IP → enrich with:
   │       - GeoIP (country, city, lat/lon)
   │       - ASN + hosting organization
   │       - Hosting type (bulletproof? tor? residential?)
   │       - IP↔domain correlation (brand-geo mismatch)
   │       → Adjust risk score based on IP signals
   │
   ├── Step 5: WHOIS + SSL Enrichment
   │   └── Domain age, registrar reputation, privacy, SSL cert validity
   │
   └── Step 6: Explainability
       └── Generate ranked, human-readable reasons
```

### Engine 2: Server-Side URL Attack Detection

```
Input: Apache/Nginx access log (or raw request lines)
   │
   ├── Step 1: Parse Log
   │   └── Extract IP, timestamp, method, target URL, status code
   │
   ├── Step 2: Decode Payload
   │   └── URL-decode (handles %xx, nested encoding, + as space)
   │
   ├── Step 3: Signature Detection (high precision)
   │   └── Pattern-match for:
   │       - SQL Injection (UNION SELECT, OR 1=1, etc.)
   │       - XSS (<script>, onerror=, javascript:, etc.)
   │       - Path Traversal (../../../etc/passwd)
   │       - Command Injection (;cat /etc/passwd, |whoami)
   │       - LFI/RFI (include=, file:///etc/)
   │
   ├── Step 4: ML Classification (TF-IDF + classifier)
   │   └── Char n-gram TF-IDF → classifier → anomaly probability
   │       (catches novel/obfuscated payloads missed by signatures)
   │
   ├── Step 5: Attacker IP Aggregation
   │   └── Group detections by source IP → build attacker profiles:
   │       - Total attack count
   │       - Technique diversity (how many attack types)
   │       - Request velocity (attacks per second)
   │       - Infrastructure risk (bulletproof? known-bad ASN?)
   │       → Ranked attacker score
   │
   └── Step 6: IP Intelligence + Explainability
       └── Geolocate each attacker IP → reasons → dashboard + map
```

---

## 🏋️ Training Your Own Models

### Train with Real Datasets (Recommended)

```powershell
# Step 1: Build the URL dataset from public threat feeds
cd backend
python training/build_url_dataset.py
# This downloads:
#   - URLhaus (malicious URLs)
#   - Majestic Million (reputable domains for benign examples)
#   - Generates brand-impersonation samples

# Step 2: Build domain reputation lists (allowlist + blocklist)
python training/build_reputation.py

# Step 3: Train the URL classifier
python training/train_url.py
# → Outputs: app/ml/models/url_xgb.pkl

# Step 4: Train the payload classifier
# (Place csic2010.csv in training/data/ for HTTP CSIC 2010 benchmark)
python training/train_payload.py
# → Outputs: app/ml/models/payload_clf.pkl

# Step 5: Validate the model (acceptance test)
python training/validate_url_model.py
# → Confirms: legit URLs → SAFE, phishing URLs → MALICIOUS
```

### Auto-Update Threat Feeds

```powershell
# Manual update
python training/update_feeds.py

# Update + retrain + validate
python training/update_feeds.py --retrain

# Schedule daily updates (Windows Task Scheduler)
schtasks /Create /TN ZenithalFeedUpdate /TR "powershell -ExecutionPolicy Bypass -File backend\scheduled_update.ps1" /SC DAILY /ST 03:00 /F

# Schedule daily updates (Linux/macOS cron)
# 0 3 * * * cd /app/backend && python training/update_feeds.py
```

---

## 🚢 Production Deployment

### Docker Compose (Recommended)

```bash
docker compose up --build
# Dashboard: http://localhost:8080
# API:       http://localhost:8000
```

### Postgres (Instead of SQLite)

```bash
pip install asyncpg
DATABASE_URL=postgresql+asyncpg://user:pass@db-host:5432/zenithal
```

### Redis Cache + Shared Rate Limiting

```bash
pip install redis
REDIS_URL=redis://redis-host:6379/0
CACHE_TTL=900
```

### API Key Authentication

```bash
REQUIRE_API_KEY=true
API_KEYS=key-for-alice,key-for-bob
# Clients send: X-API-Key: <key>
```

### HTTPS (TLS Termination)

```
# Example: Caddy (auto HTTPS)
zenithal.example.com {
    reverse_proxy /api/*  backend:8000
    reverse_proxy         dashboard:80
}
```

### Alerts (Slack / Telegram)

```bash
# Slack
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Telegram
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=987654321
ALERT_MIN_VERDICT=MALICIOUS
```

### Horizontal Scaling

```bash
# Multiple workers
uvicorn app.main:app --workers 4
# or
gunicorn -k uvicorn.workers.UvicornWorker -w 4 app.main:app

# Behind a load balancer with shared Postgres + Redis
```

> Full guide: [`docs/PRODUCTION.md`](docs/PRODUCTION.md)

---

## 🔧 Integrations (WAF, Log Agent)

### Drop-in WAF Middleware

Protect **any** FastAPI/Starlette app from SQLi/XSS/traversal in two lines:

```python
from integrations.waf_middleware import ZenithalWAF
app.add_middleware(ZenithalWAF, report_url="http://127.0.0.1:8000")
```

**Demo:**

```powershell
cd zenithal
python -m uvicorn integrations.example_protected_app:app --port 9000
```

```bash
curl "http://127.0.0.1:9000/products?id=5"                      # 200 OK
curl "http://127.0.0.1:9000/products?id=1' OR '1'='1"           # 403 BLOCKED (SQLi)
curl "http://127.0.0.1:9000/search?q=<script>alert(1)</script>" # 403 BLOCKED (XSS)
```

### Live Log Agent

Watch a live access log and stream attacks to the dashboard automatically:

```powershell
python integrations/log_agent.py C:\path\to\access.log --url http://127.0.0.1:8000
```

---

## 🎬 3-Minute Demo Flow

| Time | Action | What to Say |
|---|---|---|
| **0:00** | Open dashboard → show stats bar | "Over a billion phishing attacks hit users in 2023. Zenithal identifies URL-based attacks from IP data." |
| **0:20** | **URL Scanner** → scan `sbi-verify-now.top` | "MALICIOUS, 95/100 — brand impersonation, high-risk TLD, no HTTPS. A human analyst can trust this." |
| **0:55** | **WhatsApp Guard** → paste scam message | "This is how users get attacked — over WhatsApp and SMS. Zenithal blocks the link before it opens." |
| **1:25** | **Log Analyzer** → upload `demo/sample_access.log` | "Now the other half: 18 URL-based attacks — SQLi, XSS, traversal — grouped by attacker IP." |
| **2:10** | **Attacker Map** → show pins | "Every attacker IP geolocated from real IP data and plotted live." |
| **2:35** | Close | "Zenithal identifies URL-based attacks from IP data — for both phishing links and server exploits." |

> Full timed script: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md)

---

## 📊 Measured Accuracy & Datasets

| Model | Dataset | Result |
|---|---|---|
| **Engine 2 (Server attacks)** | HTTP **CSIC 2010** (61,065 real requests) | **95.4% accuracy** |
| **Engine 1 (Phishing URLs)** | **URLhaus** (malicious) + **Majestic Million** (benign) | **<1% false-positive rate** on 6,000 unseen legit sites |
| **IP Geolocation** | MaxMind **GeoLite2** City + ASN | Live per-IP country/city/ASN/org |

### Reproduce

```powershell
python training/build_url_dataset.py    # Download + build dataset
python training/train_url.py            # Train Engine 1
python training/train_payload.py        # Train Engine 2
python training/validate_url_model.py   # Run acceptance tests
```

---

## 📋 Environment Variables Reference

| Variable | Default | Purpose |
|---|---|---|
| `REQUIRE_API_KEY` | `false` | Enforce `X-API-Key` on scan endpoints |
| `API_KEYS` | `zenithal-dev-key` | Accepted keys (comma-separated) |
| `RATE_LIMIT_MAX` | `120` | Requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window duration (seconds) |
| `DATABASE_URL` | SQLite file | Postgres DSN for production |
| `REDIS_URL` | *(empty)* | Enable Redis cache/limits |
| `CACHE_TTL` | `900` | Cache lifetime (seconds) |
| `ALERT_WEBHOOK_URL` | *(empty)* | Slack/generic alert webhook |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Telegram bot token |
| `TELEGRAM_CHAT_ID` | *(empty)* | Telegram alert chat ID |
| `ALERT_MIN_VERDICT` | `MALICIOUS` | Minimum severity to alert |
| `SENTRY_DSN` | *(empty)* | Error monitoring (Sentry) |
| `CORS_ORIGINS` | `*` | Allowed origins (comma-separated) |
| `ENABLE_ONLINE_ENRICHMENT` | `false` | Allow live WHOIS/reputation lookups |
| `TELEGRAM_HTTP_API` | *(empty)* | Telegram bot polling token |

---

## 🗺️ Known Limitations & Roadmap

### Current Limitations

- SQLite is used by default (suitable for demos; swap to Postgres for production)
- Some model assets use synthetic training data — production accuracy improves with real datasets
- WhatsApp bot folder exists but full standalone bot isn't implemented (WhatsApp scanning works through text analysis + Android notification listener)
- PCAP ingestion is designed-for but access-log analysis is the shipped path

### Roadmap

- [ ] PCAP/NetFlow ingestion for network-level URL attack detection
- [ ] Native iOS app (SwiftUI)
- [ ] Browser extension for Firefox and Edge
- [ ] Federated learning for community model updates
- [ ] Enterprise SSO (SAML/OIDC) integration
- [ ] Kafka/NATS event bus for high-throughput deployments
- [ ] Visual similarity detection (screenshot + perceptual hash for brand impersonation)

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create a feature branch:** `git checkout -b feature/amazing-feature`
3. **Commit your changes:** `git commit -m "Add amazing feature"`
4. **Push to the branch:** `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Workflow

```powershell
# Backend
cd backend
pip install -r requirements.txt
python -m pytest tests/       # Run tests
python -m uvicorn app.main:app --reload --port 8000

# Dashboard
cd dashboard
npm install
npm run dev

# Run all checks
python training/validate_url_model.py  # Model acceptance test
python backend/test_mock.py            # Mock-based tests
```

---

## 📄 License

This project is built for the **Smart India Hackathon (SIH25229)** by **Team Zenithal**.

---

## 📚 Additional Documentation

| Document | Description |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | How to use & demo on PC, mobile, and as a developer |
| [`docs/PRODUCTION.md`](docs/PRODUCTION.md) | Auth, rate-limiting, Postgres, Redis, alerts, scaling |
| [`docs/PS_MAPPING.md`](docs/PS_MAPPING.md) | Problem-statement mapping + measured accuracy |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | Timed 3-minute pitch script |

---

<div align="center">

**Built with 🔒 by Team Zenithal for SIH25229**

*Identification of URL-Based Attacks from IP Data*

</div>
