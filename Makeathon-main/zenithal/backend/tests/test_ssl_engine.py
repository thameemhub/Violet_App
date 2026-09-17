"""
Zenithal — Tests for ssl_engine.py

Covers:
  (a) Valid long-established cert (trusted CA)
  (b) Fresh Let's Encrypt cert (<7 days old)
  (c) Self-signed cert
  (d) Expired cert
  (e) No-HTTPS domain
  (f) Connection timeout / failure
  (g) Helper functions
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engines.ssl_engine import (
    get_ssl_intelligence,
    _build_result,
    _default_result,
    _no_https_result,
    _is_self_signed,
    _is_wildcard,
    _lookup_issuer_trust,
    _compute_ssl_risk,
    _dn_to_dict,
    _parse_cert_date,
    DEFAULT_UNKNOWN_ISSUER_RISK,
)


# ---------------------------------------------------------------------------
# Mock certificate dicts (simulating ssl.SSLSocket.getpeercert() output)
# ---------------------------------------------------------------------------

def _make_cert(*, issuer_org="DigiCert Inc", issuer_cn="DigiCert SHA2 Extended",
               subject_org="Google LLC", subject_cn="*.google.com",
               not_before_dt=None, not_after_dt=None,
               san=None, self_signed=False, valid=True):
    """Build a mock certificate dict in Python ssl module format."""
    now = datetime.now(timezone.utc)
    if not_before_dt is None:
        not_before_dt = now - timedelta(days=365)
    if not_after_dt is None:
        not_after_dt = now + timedelta(days=365)

    if self_signed:
        issuer_org = subject_org
        issuer_cn = subject_cn

    issuer = (
        (("organizationName", issuer_org),),
        (("commonName", issuer_cn),),
    )
    subject = (
        (("organizationName", subject_org),) if subject_org else (),
        (("commonName", subject_cn),),
    )
    # Remove empty tuples from subject
    subject = tuple(s for s in subject if s)

    cert = {
        "issuer": issuer if not self_signed else subject,
        "subject": subject,
        "notBefore": not_before_dt.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": not_after_dt.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": san or (("DNS", subject_cn),),
        "_valid": valid,
    }
    return cert


# -----------------------------------------------------------------------
# (a) Valid long-established cert (trusted CA, e.g. Google)
# -----------------------------------------------------------------------
class TestValidEstablishedCert:
    def test_low_risk_score(self):
        cert = _make_cert(
            issuer_org="DigiCert Inc",
            subject_org="Google LLC",
            subject_cn="*.google.com",
            not_before_dt=datetime.now(timezone.utc) - timedelta(days=180),
            not_after_dt=datetime.now(timezone.utc) + timedelta(days=180),
            valid=True,
        )
        result = _build_result("google.com", cert)
        assert result["lookup_failed"] is False
        assert result["ssl_exists"] is True
        assert result["valid"] is True
        assert result["self_signed"] is False
        assert result["risk_score"] <= 5, f"Trusted CA + valid cert should be very low risk, got {result['risk_score']}"

    def test_issuer_detected(self):
        cert = _make_cert(issuer_org="DigiCert Inc")
        result = _build_result("example.com", cert)
        assert result["issuer"] == "DigiCert Inc"
        assert result["issuer_trust_tier"] <= 0.1

    def test_has_organization(self):
        cert = _make_cert(subject_org="Google LLC")
        result = _build_result("google.com", cert)
        assert result["has_organization"] == 1
        assert result["subject_organization"] == "Google LLC"


# -----------------------------------------------------------------------
# (b) Fresh Let's Encrypt cert (<7 days old)
# -----------------------------------------------------------------------
class TestFreshLetsEncrypt:
    def test_fresh_cert_risk(self):
        cert = _make_cert(
            issuer_org="Let's Encrypt",
            issuer_cn="R3",
            subject_org="",
            subject_cn="phishing-test.xyz",
            not_before_dt=datetime.now(timezone.utc) - timedelta(days=1),
            not_after_dt=datetime.now(timezone.utc) + timedelta(days=89),
            valid=True,
        )
        result = _build_result("phishing-test.xyz", cert)
        assert result["certificate_age_days"] <= 2
        # Fresh cert (+15) but valid and LE isn't unknown → risk should be moderate
        assert result["risk_score"] >= 15
        assert result["risk_score"] <= 30

    def test_no_organization(self):
        cert = _make_cert(subject_org="", issuer_org="Let's Encrypt")
        result = _build_result("test.com", cert)
        assert result["has_organization"] == 0

    def test_letsencrypt_trust_tier(self):
        """Let's Encrypt should have a moderate tier (0.3), not high risk."""
        assert _lookup_issuer_trust("Let's Encrypt") == 0.3
        assert _lookup_issuer_trust("R3") == 0.3


# -----------------------------------------------------------------------
# (c) Self-signed cert
# -----------------------------------------------------------------------
class TestSelfSignedCert:
    def test_self_signed_detected(self):
        cert = _make_cert(
            subject_org="Evil Corp",
            subject_cn="evil.example.com",
            self_signed=True,
            valid=False,
        )
        result = _build_result("evil.example.com", cert)
        assert result["self_signed"] is True
        # Self-signed (+20) + not valid (+25) = 45
        assert result["risk_score"] >= 40

    def test_self_signed_flag_in_issuer(self):
        """issuer DN == subject DN → self-signed."""
        dn = ((("organizationName", "Test"),), (("commonName", "test.local"),))
        assert _is_self_signed(dn, dn) is True

    def test_not_self_signed(self):
        issuer = ((("organizationName", "DigiCert"),),)
        subject = ((("organizationName", "Google"),),)
        assert _is_self_signed(issuer, subject) is False


# -----------------------------------------------------------------------
# (d) Expired cert
# -----------------------------------------------------------------------
class TestExpiredCert:
    def test_expired_high_risk(self):
        cert = _make_cert(
            issuer_org="DigiCert Inc",
            not_before_dt=datetime.now(timezone.utc) - timedelta(days=400),
            not_after_dt=datetime.now(timezone.utc) - timedelta(days=30),
            valid=False,
        )
        result = _build_result("expired.example.com", cert)
        assert result["valid"] is False
        assert result["days_until_expiry"] < 0
        # Not valid (+25), but trusted issuer (-5) → 20
        assert result["risk_score"] >= 15

    def test_still_extracts_issuer(self):
        """Even an expired cert should have issuer/age extracted."""
        cert = _make_cert(
            issuer_org="Sectigo Limited",
            not_after_dt=datetime.now(timezone.utc) - timedelta(days=10),
            valid=False,
        )
        result = _build_result("expired2.example.com", cert)
        assert result["issuer"] == "Sectigo Limited"
        assert result["certificate_age_days"] is not None


# -----------------------------------------------------------------------
# (e) No-HTTPS domain
# -----------------------------------------------------------------------
class TestNoHTTPS:
    def test_no_https_result(self):
        result = _no_https_result("http-only.example.com")
        assert result["ssl_exists"] is False
        assert result["lookup_failed"] is False
        assert result["issuer"] is None
        assert result["risk_score"] == 35  # moderate-high fixed score
        assert result["valid"] is False

    def test_no_https_domain_field(self):
        result = _no_https_result("test.com")
        assert result["domain"] == "test.com"


# -----------------------------------------------------------------------
# (f) Connection timeout / failure
# -----------------------------------------------------------------------
class TestLookupFailure:
    def test_empty_domain(self):
        result = get_ssl_intelligence("")
        assert result["lookup_failed"] is True
        assert result["risk_score"] == 30

    def test_default_result(self):
        result = _default_result("fail.com", reason="connection refused")
        assert result["lookup_failed"] is True
        assert result["ssl_exists"] is None
        assert result["domain"] == "fail.com"

    @patch("app.engines.ssl_engine._fetch_certificate")
    def test_timeout_returns_default(self, mock_fetch):
        mock_fetch.side_effect = TimeoutError("SSL connection timed out")
        result = get_ssl_intelligence("timeout-test.com")
        assert result["lookup_failed"] is True

    @patch("app.engines.ssl_engine._fetch_certificate")
    def test_connection_error_returns_default(self, mock_fetch):
        from app.engines.ssl_engine import _NoHTTPS
        mock_fetch.side_effect = _NoHTTPS("Connection refused")
        result = get_ssl_intelligence("no-https.com")
        assert result["ssl_exists"] is False
        assert result["lookup_failed"] is False  # not a failure, just no HTTPS


# -----------------------------------------------------------------------
# (g) Helper function tests
# -----------------------------------------------------------------------
class TestHelpers:
    def test_dn_to_dict(self):
        dn = (
            (("organizationName", "Google LLC"),),
            (("commonName", "*.google.com"),),
        )
        d = _dn_to_dict(dn)
        assert d["organizationName"] == "Google LLC"
        assert d["commonName"] == "*.google.com"

    def test_dn_to_dict_empty(self):
        assert _dn_to_dict(()) == {}
        assert _dn_to_dict(None) == {}

    def test_parse_cert_date(self):
        dt = _parse_cert_date("Jul 15 12:00:00 2026 GMT")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 7
        assert dt.day == 15

    def test_parse_cert_date_none(self):
        assert _parse_cert_date(None) is None
        assert _parse_cert_date("") is None

    def test_is_wildcard_cn(self):
        assert _is_wildcard("*.google.com", ()) is True
        assert _is_wildcard("google.com", ()) is False

    def test_is_wildcard_san(self):
        san = (("DNS", "*.example.com"), ("DNS", "example.com"))
        assert _is_wildcard("example.com", san) is True

    def test_issuer_trust_known(self):
        assert _lookup_issuer_trust("DigiCert Inc") <= 0.1
        assert _lookup_issuer_trust("Google Trust Services") <= 0.1
        assert _lookup_issuer_trust("Sectigo Limited") <= 0.15

    def test_issuer_trust_unknown(self):
        assert _lookup_issuer_trust("Totally Unknown CA") == DEFAULT_UNKNOWN_ISSUER_RISK

    def test_issuer_trust_none(self):
        assert _lookup_issuer_trust(None) == DEFAULT_UNKNOWN_ISSUER_RISK

    def test_composite_risk_self_signed_expired(self):
        """Self-signed + expired → 20 + 25 = 45."""
        score = _compute_ssl_risk(
            self_signed=True,
            valid=False,
            certificate_age_days=100,
            issuer_trust_tier=0.7,
        )
        # 20 (self-signed) + 25 (not valid) + 10 (unknown issuer) = 55
        assert score == 55

    def test_composite_risk_trusted_valid(self):
        """Trusted CA + valid cert → -5 (clamped to 0)."""
        score = _compute_ssl_risk(
            self_signed=False,
            valid=True,
            certificate_age_days=365,
            issuer_trust_tier=0.05,
        )
        assert score == 0  # -5 clamped to 0

    def test_composite_risk_fresh_cert(self):
        """Fresh cert with valid + known issuer → just +15."""
        score = _compute_ssl_risk(
            self_signed=False,
            valid=True,
            certificate_age_days=3,
            issuer_trust_tier=0.3,
        )
        assert score == 15

    def test_composite_risk_all_bad(self):
        """All bad factors → capped at 100."""
        score = _compute_ssl_risk(
            self_signed=True,
            valid=False,
            certificate_age_days=1,
            issuer_trust_tier=0.9,
        )
        # 20 + 25 + 15 + 10 = 70
        assert score == 70

    def test_composite_risk_clamp_to_zero(self):
        """Verify negative scores clamp to 0."""
        score = _compute_ssl_risk(
            self_signed=False,
            valid=True,
            certificate_age_days=365,
            issuer_trust_tier=0.05,
        )
        assert score >= 0
