"""
Zenithal — Tests for features_ssl.py

Verifies:
  - Each derived field's mapping against known SSL engine output
  - Feature naming consistency with SSL_FEATURE_NAMES
  - Graceful handling of None/missing values
  - No collision with URL or WHOIS feature names
  - All values are plain floats
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ml.features_ssl import SSL_FEATURE_NAMES, extract_ssl_features


# -----------------------------------------------------------------------
# Feature extraction tests
# -----------------------------------------------------------------------
class TestExtractSSLFeatures:
    def test_all_feature_names_present(self):
        """Output dict must contain every key in SSL_FEATURE_NAMES."""
        ssl_data = {
            "ssl_exists": True,
            "certificate_age_days": 100,
            "days_until_expiry": 265,
            "self_signed": False,
            "has_organization": 1,
            "wildcard": True,
            "issuer_trust_tier": 0.05,
            "valid": True,
            "risk_score": 0,
            "lookup_failed": False,
        }
        features = extract_ssl_features(ssl_data)
        for name in SSL_FEATURE_NAMES:
            assert name in features, f"Missing feature: {name}"

    def test_all_values_are_floats(self):
        """All feature values must be plain floats."""
        ssl_data = {
            "ssl_exists": True,
            "certificate_age_days": 200,
            "days_until_expiry": 165,
            "self_signed": True,
            "has_organization": 0,
            "wildcard": False,
            "issuer_trust_tier": 0.7,
            "valid": False,
            "risk_score": 45,
            "lookup_failed": False,
        }
        features = extract_ssl_features(ssl_data)
        for key, val in features.items():
            assert isinstance(val, float), f"{key} is {type(val)}, expected float"

    def test_ssl_exists_encoding(self):
        """ssl_exists=True → 1.0, False → 0.0, None → 0.0."""
        assert extract_ssl_features({"ssl_exists": True})["ssl_exists"] == 1.0
        assert extract_ssl_features({"ssl_exists": False})["ssl_exists"] == 0.0
        assert extract_ssl_features({"ssl_exists": None})["ssl_exists"] == 0.0

    def test_self_signed_encoding(self):
        assert extract_ssl_features({"self_signed": True})["ssl_self_signed"] == 1.0
        assert extract_ssl_features({"self_signed": False})["ssl_self_signed"] == 0.0

    def test_valid_encoding(self):
        assert extract_ssl_features({"valid": True})["ssl_valid"] == 1.0
        assert extract_ssl_features({"valid": False})["ssl_valid"] == 0.0

    def test_wildcard_encoding(self):
        assert extract_ssl_features({"wildcard": True})["ssl_is_wildcard"] == 1.0
        assert extract_ssl_features({"wildcard": False})["ssl_is_wildcard"] == 0.0

    def test_lookup_failed_encoding(self):
        assert extract_ssl_features({"lookup_failed": True})["ssl_lookup_failed"] == 1.0
        assert extract_ssl_features({"lookup_failed": False})["ssl_lookup_failed"] == 0.0

    def test_missing_fields_default_gracefully(self):
        """An empty dict should not crash — all values should be defaults."""
        features = extract_ssl_features({})
        assert features["ssl_exists"] == 0.0
        assert features["ssl_certificate_age_days"] == 0.0
        assert features["ssl_issuer_trust_tier"] == 0.7  # default unknown
        assert features["ssl_risk_score"] == 30.0  # default
        assert features["ssl_lookup_failed"] == 0.0

    def test_none_age_days(self):
        """certificate_age_days=None → 0.0."""
        features = extract_ssl_features({"certificate_age_days": None})
        assert features["ssl_certificate_age_days"] == 0.0

    def test_risk_score_passthrough(self):
        """risk_score should be passed through directly as float."""
        features = extract_ssl_features({"risk_score": 45})
        assert features["ssl_risk_score"] == 45.0

    def test_feature_count(self):
        """Number of features should match SSL_FEATURE_NAMES length."""
        features = extract_ssl_features({})
        assert len(features) == len(SSL_FEATURE_NAMES)

    def test_has_organization_passthrough(self):
        """has_organization should pass through as float."""
        assert extract_ssl_features({"has_organization": 1})["ssl_has_organization"] == 1.0
        assert extract_ssl_features({"has_organization": 0})["ssl_has_organization"] == 0.0

    def test_negative_expiry_days(self):
        """Expired certs can have negative days_until_expiry."""
        features = extract_ssl_features({"days_until_expiry": -30})
        assert features["ssl_days_until_expiry"] == -30.0


# -----------------------------------------------------------------------
# Feature naming convention tests
# -----------------------------------------------------------------------
class TestNamingConvention:
    def test_all_names_snake_case(self):
        """All feature names should be snake_case."""
        for name in SSL_FEATURE_NAMES:
            assert name == name.lower(), f"Feature name not lowercase: {name}"
            assert " " not in name, f"Feature name contains space: {name}"
            assert "-" not in name, f"Feature name contains hyphen: {name}"

    def test_all_prefixed_with_ssl(self):
        """All SSL feature names should start with 'ssl_'."""
        for name in SSL_FEATURE_NAMES:
            assert name.startswith("ssl_"), f"Feature name missing 'ssl_' prefix: {name}"

    def test_no_collision_with_url_features(self):
        """SSL feature names must not overlap with URL feature names."""
        from app.ml.features_url import FEATURE_NAMES as URL_FEATURES
        overlap = set(SSL_FEATURE_NAMES) & set(URL_FEATURES)
        assert not overlap, f"Feature name collision with URL features: {overlap}"

    def test_no_collision_with_whois_features(self):
        """SSL feature names must not overlap with WHOIS feature names."""
        from app.ml.features_whois import WHOIS_FEATURE_NAMES
        overlap = set(SSL_FEATURE_NAMES) & set(WHOIS_FEATURE_NAMES)
        assert not overlap, f"Feature name collision with WHOIS features: {overlap}"
