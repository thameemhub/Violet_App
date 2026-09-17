"""
Zenithal — URL Threat Intelligence from IP Data
Central configuration. Everything is env-overridable but ships with
demo-safe defaults so the whole stack runs offline with zero setup.
"""

import os
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default

# --- Paths ---------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BACKEND_DIR / "app"
MODELS_DIR = APP_DIR / "ml" / "models"
DATA_DIR = BACKEND_DIR / "data"
TRAINING_DIR = BACKEND_DIR / "training"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# --- Model artifacts -----------------------------------------------------
URL_MODEL_PATH = MODELS_DIR / "url_xgb.pkl"
URL_FEATURE_NAMES_PATH = MODELS_DIR / "url_feature_names.json"
PAYLOAD_MODEL_PATH = MODELS_DIR / "payload_clf.pkl"

# --- IP intelligence -----------------------------------------------------
# Optional MaxMind GeoLite2 databases. If present, real geolocation/ASN is
# used; otherwise the bundled offline reference table takes over so the demo
# always works without a MaxMind signup.
GEOIP_CITY_DB = DATA_DIR / "GeoLite2-City.mmdb"
GEOIP_ASN_DB = DATA_DIR / "GeoLite2-ASN.mmdb"
IP_REFERENCE_PATH = DATA_DIR / "ip_reference.json"

# --- Domain reputation (allowlist / blocklist) ---------------------------
# Built by training/build_reputation.py from Majestic (reputable) + URLhaus
# (malicious). Domain reputation is the most reliable anti-phishing signal.
ALLOWLIST_PATH = DATA_DIR / "allowlist_domains.txt"
BLOCKLIST_PATH = DATA_DIR / "blocklist_hosts.txt"

# --- Database ------------------------------------------------------------
# SQLite by default (zero-infra). For production set DATABASE_URL to Postgres,
# e.g. postgresql+asyncpg://user:pass@host:5432/zenithal  (pip install asyncpg).
DB_PATH = BACKEND_DIR / "zenithal.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")

# --- Verdict thresholds (0-100 risk score) -------------------------------
THRESHOLD_MALICIOUS = 70.0
THRESHOLD_SUSPICIOUS = 40.0

# --- API -----------------------------------------------------------------
API_PREFIX = "/api/v1"
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# --- Security (all opt-in so the demo runs with zero setup) --------------
# Enable API-key auth by setting REQUIRE_API_KEY=true and providing keys.
REQUIRE_API_KEY = _env_bool("REQUIRE_API_KEY", False)
# Comma-separated keys accepted in the `X-API-Key` header.
API_KEYS = set(k.strip() for k in os.getenv("API_KEYS", "zenithal-dev-key").split(",") if k.strip())
# Per-key/per-IP rate limit (requests per window). 0 disables.
RATE_LIMIT_MAX = _env_int("RATE_LIMIT_MAX", 120)      # requests
RATE_LIMIT_WINDOW = _env_int("RATE_LIMIT_WINDOW", 60)  # seconds

# --- Cache (optional Redis; falls back to in-process cache) --------------
REDIS_URL = os.getenv("REDIS_URL", "")  # e.g. redis://localhost:6379/0
CACHE_TTL = _env_int("CACHE_TTL", 900)  # seconds

# --- Alerts (optional; posts on MALICIOUS detections) --------------------
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")   # generic/Slack webhook
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
ALERT_MIN_VERDICT = os.getenv("ALERT_MIN_VERDICT", "MALICIOUS")  # or SUSPICIOUS

# --- Error monitoring (optional Sentry) ----------------------------------
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

# --- Online enrichment (optional, off by default for demo reliability) ---
ENABLE_ONLINE_ENRICHMENT = _env_bool("ENABLE_ONLINE_ENRICHMENT", False)


def score_to_verdict(score: float) -> str:
    """Map a 0-100 risk score to a verdict label."""
    if score >= THRESHOLD_MALICIOUS:
        return "MALICIOUS"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "SAFE"
