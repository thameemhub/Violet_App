"""
Zenithal — SSL Certificate Feature Extractor.

Converts the raw + derived dict from ``ssl_engine.get_ssl_intelligence()``
into a flat ``dict[str, float]`` following the same conventions as
``features_url.py`` and ``features_whois.py``:
  - All keys are snake_case, prefixed with ``ssl_``
  - All values are plain floats (booleans as 0.0 / 1.0)
  - No normalization/scaling applied (raw values fed to fusion / ML)

This module does NOT inject features into the existing 38-feature XGBoost
vector.  Under Option A (no retraining), SSL features are combined into
the final threat score via weighted fusion only.
"""

SSL_FEATURE_NAMES: list[str] = [
    "ssl_exists",
    "ssl_certificate_age_days",
    "ssl_days_until_expiry",
    "ssl_self_signed",
    "ssl_has_organization",
    "ssl_is_wildcard",
    "ssl_issuer_trust_tier",
    "ssl_valid",
    "ssl_risk_score",
    "ssl_lookup_failed",
]


def extract_ssl_features(ssl_data: dict) -> dict[str, float]:
    """
    Convert SSL engine output dict into the numeric feature dict.

    Parameters
    ----------
    ssl_data : dict
        Output from ``ssl_engine.get_ssl_intelligence()``.

    Returns
    -------
    dict[str, float]
        Feature dict keyed by ``SSL_FEATURE_NAMES``.  Missing / None
        source values resolve to neutral defaults.
    """
    f: dict[str, float] = {}

    f["ssl_exists"] = 1.0 if ssl_data.get("ssl_exists") else 0.0
    f["ssl_certificate_age_days"] = float(ssl_data.get("certificate_age_days") or 0)
    f["ssl_days_until_expiry"] = float(ssl_data.get("days_until_expiry") or 0)
    f["ssl_self_signed"] = 1.0 if ssl_data.get("self_signed") else 0.0
    f["ssl_has_organization"] = float(ssl_data.get("has_organization", 0))
    f["ssl_is_wildcard"] = 1.0 if ssl_data.get("wildcard") else 0.0
    f["ssl_issuer_trust_tier"] = float(ssl_data.get("issuer_trust_tier", 0.7))
    f["ssl_valid"] = 1.0 if ssl_data.get("valid") else 0.0
    f["ssl_risk_score"] = float(ssl_data.get("risk_score", 30))
    f["ssl_lookup_failed"] = 1.0 if ssl_data.get("lookup_failed") else 0.0

    return f
