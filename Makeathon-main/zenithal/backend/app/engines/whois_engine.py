"""
Zenithal — Engine 3: WHOIS/RDAP Domain Intelligence.

Performs WHOIS lookups and converts registration metadata into numeric risk
features.  Designed to run in parallel with the lexical URL engine (Engine 1)
and IP intelligence, feeding a fused threat score.

Error handling is defensive throughout: WHOIS lookups are unreliable
(timeouts, partial data, rate-limiting, ccTLD quirks).  A failed lookup
must NEVER crash the pipeline — it returns a safe default dict with
``lookup_failed: True`` instead.
"""

import logging
import re
import socket
from datetime import datetime, timezone
from functools import lru_cache

from app.engines.whois_constants import (
    COUNTRY_RISK,
    DEFAULT_UNKNOWN_COUNTRY_RISK,
    DEFAULT_UNKNOWN_REGISTRAR_RISK,
    PRIVACY_SERVICE_KEYWORDS,
    REGISTRAR_REPUTATION,
    SUSPICIOUS_STATUS_CODES,
)

logger = logging.getLogger("zenithal.whois")

# We import python-whois lazily to keep the module importable even if the
# package is missing (graceful degradation).
_whois = None
try:
    import whois as _whois  # type: ignore[import-untyped]
except ImportError:
    logger.warning("python-whois not installed — WHOIS engine will return defaults")

# Default socket timeout for WHOIS lookups (seconds).
_WHOIS_TIMEOUT_S = 5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_whois_intelligence(domain: str) -> dict:
    """
    Perform WHOIS/RDAP lookup and return raw + derived risk fields.

    Must not raise on lookup failure — returns a safe default dict with
    ``lookup_failed: True`` instead.
    """
    if not domain or _whois is None:
        return _default_result(domain or "", reason="whois library unavailable")

    try:
        raw = _safe_whois_lookup(domain)
    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return _default_result(domain, reason=str(exc))

    if raw is None:
        return _default_result(domain, reason="empty WHOIS response")

    return _build_result(domain, raw)


@lru_cache(maxsize=2048)
def get_whois_intelligence_cached(domain: str) -> dict:
    """Cached wrapper — avoids repeat lookups within the same process."""
    return get_whois_intelligence(domain)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _safe_whois_lookup(domain: str) -> object | None:
    """Run python-whois with a socket timeout guard."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_WHOIS_TIMEOUT_S)
        result = _whois.whois(domain)
        # python-whois returns an object even for failed lookups; check for
        # a meaningful field to decide if we actually got data.
        if result is None:
            return None
        # Some responses come back with domain_name=None for non-existent domains
        dn = result.get("domain_name") if hasattr(result, "get") else getattr(result, "domain_name", None)
        if dn is None:
            return None
        return result
    except Exception as exc:
        # Catch absolutely everything: network errors, parse errors,
        # rate-limit responses disguised as data, etc.
        logger.debug("WHOIS raw lookup error for %s: %s", domain, exc)
        raise
    finally:
        socket.setdefaulttimeout(old_timeout)


def _build_result(domain: str, raw) -> dict:
    """Extract fields from a successful WHOIS response."""
    now = datetime.now(timezone.utc)

    creation_date = _to_datetime(raw.get("creation_date") if hasattr(raw, "get") else getattr(raw, "creation_date", None))
    expiration_date = _to_datetime(raw.get("expiration_date") if hasattr(raw, "get") else getattr(raw, "expiration_date", None))
    updated_date = _to_datetime(raw.get("updated_date") if hasattr(raw, "get") else getattr(raw, "updated_date", None))

    registrar = _extract_str(raw, "registrar")
    registrant_org = _extract_str(raw, "org") or _extract_str(raw, "registrant_org") or ""
    registrant_name = _extract_str(raw, "name") or _extract_str(raw, "registrant_name") or ""
    country = _extract_str(raw, "country")
    status = _extract_list(raw, "status")
    name_servers = _extract_list(raw, "name_servers")

    # --- Derived numeric fields ---
    domain_age_days = _days_between(creation_date, now) if creation_date else None
    registration_period_days = _days_between(creation_date, expiration_date) if (creation_date and expiration_date) else None
    days_since_last_update = _days_between(updated_date, now) if updated_date else None

    privacy_enabled = _detect_privacy(registrar, registrant_org, registrant_name)
    registrar_reputation = _lookup_registrar_reputation(registrar)
    status_flags = _count_suspicious_status(status)
    number_nameservers = len(name_servers) if name_servers else 0
    country_risk = _lookup_country_risk(country)
    domain_age_risk = _compute_age_risk(domain_age_days)

    # --- Composite risk score (0–100, capped) ---
    risk_score = _compute_composite_risk(
        domain_age_days=domain_age_days,
        privacy_enabled=privacy_enabled,
        registration_period_days=registration_period_days,
        registrar_reputation=registrar_reputation,
        days_since_last_update=days_since_last_update,
        status_flags=status_flags,
    )

    return {
        # Raw fields
        "domain": domain,
        "creation_date": _fmt_date(creation_date),
        "expiration_date": _fmt_date(expiration_date),
        "updated_date": _fmt_date(updated_date),
        "registrar": registrar,
        "registrant_org": registrant_org,
        "registrant_name": registrant_name,
        "country": country,
        "status": status,
        "name_servers": name_servers,
        # Derived numeric
        "domain_age_days": domain_age_days,
        "registration_period_days": registration_period_days,
        "days_since_last_update": days_since_last_update,
        "privacy_enabled": privacy_enabled,
        "registrar_reputation": registrar_reputation,
        "status_flags": status_flags,
        "number_nameservers": number_nameservers,
        "country_risk": country_risk,
        "domain_age_risk": domain_age_risk,
        # Final
        "risk_score": risk_score,
        "lookup_failed": False,
    }


def _default_result(domain: str, *, reason: str = "unknown") -> dict:
    """Safe fallback when WHOIS lookup fails or is unavailable."""
    return {
        "domain": domain,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrar": None,
        "registrant_org": None,
        "registrant_name": None,
        "country": None,
        "status": [],
        "name_servers": [],
        "domain_age_days": None,
        "registration_period_days": None,
        "days_since_last_update": None,
        "privacy_enabled": False,
        "registrar_reputation": DEFAULT_UNKNOWN_REGISTRAR_RISK,
        "status_flags": 0,
        "number_nameservers": 0,
        "country_risk": DEFAULT_UNKNOWN_COUNTRY_RISK,
        "domain_age_risk": 50,  # neutral default when unknown
        "risk_score": 50,       # neutral — don't bias the fusion either way
        "lookup_failed": True,
        "lookup_failed_reason": reason,
    }


# ---------------------------------------------------------------------------
# Field extraction helpers (python-whois returns inconsistent types)
# ---------------------------------------------------------------------------

def _to_datetime(value) -> datetime | None:
    """Coerce a value (possibly a list) to a single datetime."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        # Try common WHOIS date formats
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                     "%d-%b-%Y", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                dt = datetime.strptime(value.strip()[:19], fmt)
                return dt.replace(tzinfo=timezone.utc)
            except (ValueError, IndexError):
                continue
    return None


def _extract_str(raw, key: str) -> str | None:
    """Get a string field from a WHOIS result, handling list-wrapped values."""
    val = raw.get(key) if hasattr(raw, "get") else getattr(raw, key, None)
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val).strip() if val else None


def _extract_list(raw, key: str) -> list[str]:
    """Get a list field, normalizing scalars to single-item lists."""
    val = raw.get(key) if hasattr(raw, "get") else getattr(raw, key, None)
    if val is None:
        return []
    if isinstance(val, str):
        return [val.strip().lower()] if val.strip() else []
    if isinstance(val, (list, tuple, set)):
        return [str(v).strip().lower() for v in val if v]
    return [str(val).strip().lower()]


def _days_between(start: datetime | None, end: datetime | None) -> int | None:
    """Days between two datetimes. Returns None if either is missing."""
    if start is None or end is None:
        return None
    delta = end - start
    return max(int(delta.total_seconds() / 86400), 0)


def _fmt_date(dt: datetime | None) -> str | None:
    """Format a datetime as ISO string for JSON output."""
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Risk computation helpers
# ---------------------------------------------------------------------------

_STRIP_RE = re.compile(r"[^a-z0-9\s&]")


def _normalize_registrar(registrar: str | None) -> str:
    """Lowercase + strip punctuation for fuzzy registrar matching."""
    if not registrar:
        return ""
    return _STRIP_RE.sub("", registrar.lower()).strip()


def _detect_privacy(registrar: str | None, org: str, name: str) -> bool:
    """True if any registrant field suggests privacy/proxy service."""
    combined = " ".join([registrar or "", org, name]).lower()
    return any(kw in combined for kw in PRIVACY_SERVICE_KEYWORDS)


def _lookup_registrar_reputation(registrar: str | None) -> float:
    """Return 0–1 risk score for registrar. Lower = more reputable."""
    norm = _normalize_registrar(registrar)
    if not norm:
        return DEFAULT_UNKNOWN_REGISTRAR_RISK

    # Exact match first
    if norm in REGISTRAR_REPUTATION:
        return REGISTRAR_REPUTATION[norm]

    # Substring fallback — check if any known registrar name is contained
    for key, score in REGISTRAR_REPUTATION.items():
        if key in norm or norm in key:
            return score

    return DEFAULT_UNKNOWN_REGISTRAR_RISK


def _count_suspicious_status(status_list: list[str]) -> int:
    """Count how many suspicious EPP status codes are present."""
    count = 0
    for s in status_list:
        s_lower = s.lower().split()[0] if s else ""  # status may include URL
        if any(code in s_lower for code in SUSPICIOUS_STATUS_CODES):
            count += 1
    return count


def _lookup_country_risk(country: str | None) -> float:
    """Return 0–1 risk score for registrant country."""
    if not country:
        return DEFAULT_UNKNOWN_COUNTRY_RISK
    code = country.strip().upper()[:2]
    return COUNTRY_RISK.get(code, DEFAULT_UNKNOWN_COUNTRY_RISK)


def _compute_age_risk(domain_age_days: int | None) -> int:
    """Map domain age to a 0–100 risk score using specified thresholds."""
    if domain_age_days is None:
        return 50  # neutral when unknown
    if domain_age_days >= 1825:    # ≥ 5 years
        return 5
    if domain_age_days >= 365:     # ≥ 1 year
        return 20
    if domain_age_days >= 180:     # ≥ 6 months
        return 30
    if domain_age_days >= 30:      # ≥ 1 month
        return 50
    if domain_age_days >= 7:       # ≥ 1 week
        return 80
    return 100                     # < 7 days


def _compute_composite_risk(
    *,
    domain_age_days: int | None,
    privacy_enabled: bool,
    registration_period_days: int | None,
    registrar_reputation: float,
    days_since_last_update: int | None,
    status_flags: int,
) -> int:
    """
    Composite WHOIS risk score (0–100, capped).

    Scoring formula per spec:
      +40  if domain_age_days < 7
      +15  if privacy_enabled
      +15  if registration_period_days <= 365
      +10  if registrar unknown (reputation >= 0.8)
      +10  if days_since_last_update < 7
      +10  if status_flags > 0
    """
    score = 0

    if domain_age_days is not None and domain_age_days < 7:
        score += 40
    elif domain_age_days is None:
        score += 20  # unknown age is mildly suspicious

    if privacy_enabled:
        score += 15

    if registration_period_days is not None and registration_period_days <= 365:
        score += 15
    elif registration_period_days is None:
        score += 5  # unknown period is slightly suspicious

    if registrar_reputation >= 0.8:
        score += 10

    if days_since_last_update is not None and days_since_last_update < 7:
        score += 10

    if status_flags > 0:
        score += 10

    return min(score, 100)
