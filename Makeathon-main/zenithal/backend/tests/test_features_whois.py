"""
Zenithal — Tests for features_whois.py

Verifies:
  - Each derived field's math against known inputs
  - Age-risk boundary values (6/7/29/30/179/180/364/365/1825+ days)
  - Feature naming consistency with WHOIS_FEATURE_NAMES
  - Graceful handling of None/missing values in WHOIS data
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ml.features_whois import WHOIS_FEATURE_NAMES, extract_whois_features
from app.engines.whois_engine import _compute_age_risk


# -----------------------------------------------------------------------
# Age-risk boundary value tests (exact thresholds from spec)
# -----------------------------------------------------------------------
class TestAgeRiskBoundaries:
    """Test the domain_age_risk mapping at every boundary value."""

    @pytest.mark.parametrize("age,expected_risk", [
        # < 7 days → 100
        (0, 100),
        (1, 100),
        (6, 100),
        # 7 ≤ age < 30 → 80
        (7, 80),
        (15, 80),
        (29, 80),
        # 30 ≤ age < 180 → 50
        (30, 50),
        (90, 50),
        (179, 50),
        # 180 ≤ age < 365 → 30
        (180, 30),
        (270, 30),
        (364, 30),
        # 365 ≤ age < 1825 → 20
        (365, 20),
        (730, 20),
        (1824, 20),
        # age ≥ 1825 (5 years) → 5
        (1825, 5),
        (3650, 5),
        (10000, 5),
    ])
    def test_age_risk_thresholds(self, age, expected_risk):
        assert _compute_age_risk(age) == expected_risk

    def test_age_risk_none(self):
        """Unknown age → neutral risk of 50."""
        assert _compute_age_risk(None) == 50


# -----------------------------------------------------------------------
# Feature extraction tests
# -----------------------------------------------------------------------
class TestExtractWhoisFeatures:
    def test_all_feature_names_present(self):
        """Output dict must contain every key in WHOIS_FEATURE_NAMES."""
        whois_data = {
            "domain_age_days": 100,
            "domain_age_risk": 50,
            "registration_period_days": 365,
            "days_since_last_update": 30,
            "privacy_enabled": False,
            "registrar_reputation": 0.2,
            "status_flags": 0,
            "number_nameservers": 2,
            "country_risk": 0.1,
            "risk_score": 25,
            "lookup_failed": False,
        }
        features = extract_whois_features(whois_data)
        for name in WHOIS_FEATURE_NAMES:
            assert name in features, f"Missing feature: {name}"

    def test_all_values_are_floats(self):
        """All feature values must be plain floats."""
        whois_data = {
            "domain_age_days": 500,
            "domain_age_risk": 20,
            "registration_period_days": 730,
            "days_since_last_update": 90,
            "privacy_enabled": True,
            "registrar_reputation": 0.3,
            "status_flags": 2,
            "number_nameservers": 4,
            "country_risk": 0.2,
            "risk_score": 40,
            "lookup_failed": False,
        }
        features = extract_whois_features(whois_data)
        for key, val in features.items():
            assert isinstance(val, float), f"{key} is {type(val)}, expected float"

    def test_privacy_enabled_encoding(self):
        """privacy_enabled=True → 1.0, False → 0.0."""
        assert extract_whois_features({"privacy_enabled": True})["whois_privacy_enabled"] == 1.0
        assert extract_whois_features({"privacy_enabled": False})["whois_privacy_enabled"] == 0.0

    def test_lookup_failed_encoding(self):
        """lookup_failed=True → 1.0, False → 0.0."""
        assert extract_whois_features({"lookup_failed": True})["whois_lookup_failed"] == 1.0
        assert extract_whois_features({"lookup_failed": False})["whois_lookup_failed"] == 0.0

    def test_missing_fields_default_gracefully(self):
        """An empty dict should not crash — all values should be defaults."""
        features = extract_whois_features({})
        assert features["whois_domain_age_days"] == 0.0
        assert features["whois_domain_age_risk"] == 50.0  # default
        assert features["whois_registrar_reputation"] == 0.8  # default unknown
        assert features["whois_lookup_failed"] == 0.0

    def test_none_age_days(self):
        """domain_age_days=None → 0.0 (safe numeric default)."""
        features = extract_whois_features({"domain_age_days": None})
        assert features["whois_domain_age_days"] == 0.0

    def test_risk_score_passthrough(self):
        """risk_score should be passed through directly as float."""
        features = extract_whois_features({"risk_score": 82})
        assert features["whois_risk_score"] == 82.0

    def test_feature_count(self):
        """Number of features should match WHOIS_FEATURE_NAMES length."""
        features = extract_whois_features({})
        assert len(features) == len(WHOIS_FEATURE_NAMES)


# -----------------------------------------------------------------------
# Feature naming convention tests
# -----------------------------------------------------------------------
class TestNamingConvention:
    def test_all_names_snake_case(self):
        """All feature names should be snake_case."""
        for name in WHOIS_FEATURE_NAMES:
            assert name == name.lower(), f"Feature name not lowercase: {name}"
            assert " " not in name, f"Feature name contains space: {name}"
            assert "-" not in name, f"Feature name contains hyphen: {name}"

    def test_all_prefixed_with_whois(self):
        """All WHOIS feature names should start with 'whois_' to avoid collision."""
        for name in WHOIS_FEATURE_NAMES:
            assert name.startswith("whois_"), f"Feature name missing 'whois_' prefix: {name}"

    def test_no_collision_with_url_features(self):
        """WHOIS feature names must not overlap with URL feature names."""
        from app.ml.features_url import FEATURE_NAMES as URL_FEATURES
        overlap = set(WHOIS_FEATURE_NAMES) & set(URL_FEATURES)
        assert not overlap, f"Feature name collision: {overlap}"
