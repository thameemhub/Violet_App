"""
Zenithal — Tests for whois_engine.py

Covers:
  (a) Normal old domain — low risk expected
  (b) Freshly registered domain — high risk expected
  (c) Privacy-protected domain — privacy flag detected
  (d) Lookup failure / timeout — graceful degradation
  (e) Missing date fields — no crash
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engines.whois_engine import (
    get_whois_intelligence,
    _build_result,
    _default_result,
    _detect_privacy,
    _lookup_registrar_reputation,
    _count_suspicious_status,
    _compute_age_risk,
    _compute_composite_risk,
    _normalize_registrar,
    _lookup_country_risk,
)


# -----------------------------------------------------------------------
# (a) Normal old domain
# -----------------------------------------------------------------------
class TestOldDomain:
    def test_low_risk_score(self, old_domain_whois):
        result = _build_result("google.com", old_domain_whois)
        assert result["lookup_failed"] is False
        assert result["domain"] == "google.com"
        assert result["domain_age_days"] > 5000
        assert result["risk_score"] <= 30, f"Old reputable domain should be low risk, got {result['risk_score']}"

    def test_registrar_detected(self, old_domain_whois):
        result = _build_result("google.com", old_domain_whois)
        assert result["registrar"] == "MarkMonitor Inc."
        assert result["registrar_reputation"] < 0.2  # MarkMonitor is reputable

    def test_privacy_not_detected(self, old_domain_whois):
        result = _build_result("google.com", old_domain_whois)
        assert result["privacy_enabled"] is False

    def test_name_servers_counted(self, old_domain_whois):
        result = _build_result("google.com", old_domain_whois)
        assert result["number_nameservers"] == 4

    def test_country_risk_us(self, old_domain_whois):
        result = _build_result("google.com", old_domain_whois)
        assert result["country_risk"] == 0.1


# -----------------------------------------------------------------------
# (b) Freshly registered domain
# -----------------------------------------------------------------------
class TestFreshDomain:
    def test_high_risk_score(self, fresh_domain_whois):
        result = _build_result("phishing-test-site.xyz", fresh_domain_whois)
        assert result["lookup_failed"] is False
        assert result["domain_age_days"] <= 3
        # Young domain + unknown registrar + clientHold + short registration + recent update + RU country
        assert result["risk_score"] >= 70, f"Fresh suspicious domain should be high risk, got {result['risk_score']}"

    def test_age_under_7_days(self, fresh_domain_whois):
        result = _build_result("phishing-test-site.xyz", fresh_domain_whois)
        assert result["domain_age_risk"] == 100

    def test_registration_period_short(self, fresh_domain_whois):
        result = _build_result("phishing-test-site.xyz", fresh_domain_whois)
        assert result["registration_period_days"] is not None
        assert result["registration_period_days"] <= 365

    def test_suspicious_status(self, fresh_domain_whois):
        result = _build_result("phishing-test-site.xyz", fresh_domain_whois)
        assert result["status_flags"] >= 1  # clientHold is suspicious

    def test_country_risk_ru(self, fresh_domain_whois):
        result = _build_result("phishing-test-site.xyz", fresh_domain_whois)
        assert result["country_risk"] == 0.6


# -----------------------------------------------------------------------
# (c) Privacy-protected domain
# -----------------------------------------------------------------------
class TestPrivacyDomain:
    def test_privacy_enabled(self, privacy_domain_whois):
        result = _build_result("hidden-domain.com", privacy_domain_whois)
        assert result["privacy_enabled"] is True

    def test_risk_includes_privacy_penalty(self, privacy_domain_whois):
        result = _build_result("hidden-domain.com", privacy_domain_whois)
        # Privacy adds +15 to composite score
        assert result["risk_score"] >= 15

    def test_registrar_namecheap_reputation(self, privacy_domain_whois):
        result = _build_result("hidden-domain.com", privacy_domain_whois)
        assert result["registrar_reputation"] <= 0.3  # Namecheap is known


# -----------------------------------------------------------------------
# (d) Lookup failure / timeout
# -----------------------------------------------------------------------
class TestLookupFailure:
    def test_empty_domain_returns_default(self):
        result = get_whois_intelligence("")
        assert result["lookup_failed"] is True
        assert result["risk_score"] == 50  # neutral

    @patch("app.engines.whois_engine._whois")
    def test_timeout_returns_default(self, mock_whois):
        mock_whois.whois.side_effect = TimeoutError("WHOIS lookup timed out")
        result = get_whois_intelligence("timeout-test.com")
        assert result["lookup_failed"] is True
        assert result["risk_score"] == 50

    @patch("app.engines.whois_engine._whois")
    def test_network_error_returns_default(self, mock_whois):
        mock_whois.whois.side_effect = ConnectionError("No route to host")
        result = get_whois_intelligence("network-fail.com")
        assert result["lookup_failed"] is True
        assert result["domain"] == "network-fail.com"

    @patch("app.engines.whois_engine._whois")
    def test_empty_response_returns_default(self, mock_whois):
        mock_whois.whois.return_value = MagicMock(
            get=MagicMock(return_value=None),
            domain_name=None,
        )
        # Force hasattr to return True for get
        result = get_whois_intelligence("empty-response.com")
        assert result["lookup_failed"] is True

    def test_whois_unavailable(self):
        """When python-whois is not installed, get_whois_intelligence degrades."""
        result = _default_result("no-whois.com", reason="whois library unavailable")
        assert result["lookup_failed"] is True
        assert result["risk_score"] == 50


# -----------------------------------------------------------------------
# (e) Missing date fields (common for ccTLDs)
# -----------------------------------------------------------------------
class TestMissingDates:
    def test_none_dates_no_crash(self, none_dates_whois):
        result = _build_result("example.cn", none_dates_whois)
        assert result["lookup_failed"] is False
        assert result["domain_age_days"] is None
        assert result["registration_period_days"] is None
        assert result["days_since_last_update"] is None

    def test_neutral_age_risk_when_unknown(self, none_dates_whois):
        result = _build_result("example.cn", none_dates_whois)
        assert result["domain_age_risk"] == 50  # neutral default

    def test_country_risk_cn(self, none_dates_whois):
        result = _build_result("example.cn", none_dates_whois)
        assert result["country_risk"] == 0.5


# -----------------------------------------------------------------------
# Unit tests for helper functions
# -----------------------------------------------------------------------
class TestHelpers:
    def test_normalize_registrar(self):
        assert _normalize_registrar("GoDaddy.com, LLC") == "godaddycom llc"
        assert _normalize_registrar("MarkMonitor Inc.") == "markmonitor inc"
        assert _normalize_registrar(None) == ""
        assert _normalize_registrar("") == ""

    def test_detect_privacy_whoisguard(self):
        assert _detect_privacy(None, "WhoisGuard Protected", "") is True

    def test_detect_privacy_redacted(self):
        assert _detect_privacy("Some Registrar", "REDACTED FOR PRIVACY", "") is True

    def test_detect_privacy_none(self):
        assert _detect_privacy("GoDaddy", "Google LLC", "John Doe") is False

    def test_registrar_reputation_known(self):
        assert _lookup_registrar_reputation("GoDaddy.com, LLC") <= 0.2
        assert _lookup_registrar_reputation("MarkMonitor Inc.") <= 0.1

    def test_registrar_reputation_unknown(self):
        assert _lookup_registrar_reputation("Totally Unknown Registrar XYZ") == 0.8

    def test_registrar_reputation_none(self):
        assert _lookup_registrar_reputation(None) == 0.8

    def test_suspicious_status_count(self):
        statuses = [
            "clientHold https://icann.org/epp#clientHold",
            "ok https://icann.org/epp#ok",
            "serverHold https://icann.org/epp#serverHold",
        ]
        assert _count_suspicious_status(statuses) == 2

    def test_suspicious_status_empty(self):
        assert _count_suspicious_status([]) == 0

    def test_country_risk_lookup(self):
        assert _lookup_country_risk("US") == 0.1
        assert _lookup_country_risk("RU") == 0.6
        assert _lookup_country_risk("NG") == 0.7
        assert _lookup_country_risk(None) == 0.4
        assert _lookup_country_risk("ZZ") == 0.4  # unknown country

    def test_composite_risk_max_case(self):
        """All risk factors present → score should be capped at 100."""
        score = _compute_composite_risk(
            domain_age_days=1,
            privacy_enabled=True,
            registration_period_days=100,
            registrar_reputation=0.9,
            days_since_last_update=2,
            status_flags=3,
        )
        assert score == 100

    def test_composite_risk_min_case(self):
        """No risk factors present → score should be 0."""
        score = _compute_composite_risk(
            domain_age_days=3650,
            privacy_enabled=False,
            registration_period_days=3650,
            registrar_reputation=0.1,
            days_since_last_update=365,
            status_flags=0,
        )
        assert score == 0
