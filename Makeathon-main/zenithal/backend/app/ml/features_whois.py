"""
Zenithal — WHOIS Feature Extractor.

Converts the raw + derived dict from ``whois_engine.get_whois_intelligence()``
into a flat ``dict[str, float]`` following the same conventions as
``features_url.py``:
  - All keys are snake_case
  - All values are plain floats (booleans as 0.0 / 1.0)
  - No normalization/scaling applied (raw values fed to fusion / ML)

This module does NOT inject features into the existing 38-feature XGBoost
vector.  Under Option A (no retraining), WHOIS features are combined into
the final threat score via weighted fusion only.
"""

WHOIS_FEATURE_NAMES: list[str] = [
    "whois_domain_age_days",
    "whois_domain_age_risk",
    "whois_registration_period_days",
    "whois_days_since_last_update",
    "whois_privacy_enabled",
    "whois_registrar_reputation",
    "whois_status_flags",
    "whois_number_nameservers",
    "whois_country_risk",
    "whois_risk_score",
    "whois_lookup_failed",
]


def extract_whois_features(whois_data: dict) -> dict[str, float]:
    """
    Convert WHOIS engine output dict into the numeric feature dict.

    Parameters
    ----------
    whois_data : dict
        Output from ``whois_engine.get_whois_intelligence()``.

    Returns
    -------
    dict[str, float]
        Feature dict keyed by ``WHOIS_FEATURE_NAMES``.  Missing / None
        source values resolve to neutral defaults (0.0 or midpoint risk).
    """
    f: dict[str, float] = {}

    f["whois_domain_age_days"] = float(whois_data.get("domain_age_days") or 0)
    f["whois_domain_age_risk"] = float(whois_data.get("domain_age_risk", 50))
    f["whois_registration_period_days"] = float(whois_data.get("registration_period_days") or 0)
    f["whois_days_since_last_update"] = float(whois_data.get("days_since_last_update") or 0)
    f["whois_privacy_enabled"] = 1.0 if whois_data.get("privacy_enabled") else 0.0
    f["whois_registrar_reputation"] = float(whois_data.get("registrar_reputation", 0.8))
    f["whois_status_flags"] = float(whois_data.get("status_flags", 0))
    f["whois_number_nameservers"] = float(whois_data.get("number_nameservers", 0))
    f["whois_country_risk"] = float(whois_data.get("country_risk", 0.4))
    f["whois_risk_score"] = float(whois_data.get("risk_score", 50))
    f["whois_lookup_failed"] = 1.0 if whois_data.get("lookup_failed") else 0.0

    return f
