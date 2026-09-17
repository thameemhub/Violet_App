"""
Zenithal — SSL Certificate Intelligence Engine.

Opens a TLS connection to a domain, downloads the peer certificate, and
extracts trust-relevant fields (issuer, validity, self-signed status,
organization, wildcard).  Rather than treating HTTPS as a binary trust
signal, this module inspects the certificate itself.

Error handling is defensive throughout: connection failures, timeouts,
no-HTTPS sites, and expired certs must all degrade gracefully — a failed
lookup returns a safe default dict with ``lookup_failed: True``.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from functools import lru_cache

logger = logging.getLogger("zenithal.ssl_engine")

# Default TLS connection timeout (seconds).
_SSL_TIMEOUT_S = 5

# ---------------------------------------------------------------------------
# Issuer trust tier (starter heuristics — expand with real abuse data)
# ---------------------------------------------------------------------------
# Lower value = more trustworthy.  Keys MUST be lowercase for matching.
# An issuer being Let's Encrypt is NOT itself a red flag — it's the most
# common CA on the internet.  Its weight in the composite score stays small.
ISSUER_TRUST_TIER: dict[str, float] = {
    "google trust services": 0.05,
    "google trust services llc": 0.05,
    "digicert inc": 0.05,
    "digicert": 0.05,
    "globalsign": 0.05,
    "globalsign nv - g2": 0.05,
    "comodo ca limited": 0.1,
    "sectigo limited": 0.1,
    "sectigo": 0.1,
    "entrust": 0.1,
    "entrust, inc.": 0.1,
    "amazon": 0.1,
    "amazon trust services": 0.1,
    "microsoft corporation": 0.1,
    "apple inc.": 0.1,
    "let's encrypt": 0.3,
    "letsencrypt": 0.3,
    "r3": 0.3,               # Let's Encrypt intermediate CA common name
    "e1": 0.3,               # Let's Encrypt ECDSA intermediate
    "r10": 0.3,              # Let's Encrypt newer intermediate
    "r11": 0.3,
    "zerossl": 0.4,
    "buypass": 0.35,
    "ssl.com": 0.3,
    "cloudflare, inc.": 0.15,
    "cloudflare": 0.15,
}

DEFAULT_UNKNOWN_ISSUER_RISK: float = 0.7


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_ssl_intelligence(domain: str) -> dict:
    """
    Open a TLS connection to the domain, download the certificate, and
    extract trust-relevant fields.

    Must not raise on connection failure, timeout, or missing cert —
    returns a safe default dict with ``lookup_failed: True`` instead.
    """
    if not domain:
        return _default_result(domain or "", reason="empty domain")

    try:
        cert_dict = _fetch_certificate(domain)
    except _NoHTTPS:
        # Site does not serve HTTPS at all — distinct from "bad cert"
        return _no_https_result(domain)
    except Exception as exc:
        logger.debug("SSL lookup failed for %s: %s", domain, exc)
        return _default_result(domain, reason=str(exc))

    if cert_dict is None:
        return _default_result(domain, reason="no certificate returned")

    return _build_result(domain, cert_dict)


@lru_cache(maxsize=2048)
def get_ssl_intelligence_cached(domain: str) -> dict:
    """Cached wrapper — avoids repeat TLS handshakes within the same process."""
    return get_ssl_intelligence(domain)


# ---------------------------------------------------------------------------
# Sentinel exception for HTTP-only sites
# ---------------------------------------------------------------------------
class _NoHTTPS(Exception):
    """Raised when the domain doesn't accept TLS connections at all."""


# ---------------------------------------------------------------------------
# Certificate fetching
# ---------------------------------------------------------------------------

def _fetch_certificate(domain: str) -> dict | None:
    """
    Connect to domain:443 via TLS and return the peer certificate dict.

    Strategy:
      1. Try a *verifying* context first — this populates all cert fields
         (issuer, dates, subject) when the cert is valid.
      2. If verification fails (expired, self-signed), fall back to a
         non-verifying context to still grab what we can, then parse the
         DER binary cert for issuer/dates if available.
    """
    cert = None
    valid = False

    # --- Attempt 1: Verifying context (gives full parsed cert dict) ---
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=_SSL_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                valid = True
    except ssl.SSLCertVerificationError:
        # Cert exists but is invalid — fall through to attempt 2
        valid = False
    except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        raise _NoHTTPS(str(exc)) from exc
    except socket.timeout as exc:
        raise TimeoutError(f"SSL connection to {domain} timed out") from exc
    except Exception:
        pass  # fall through to attempt 2

    # --- Attempt 2: Non-verifying context (for expired/self-signed certs) ---
    if not cert:
        try:
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=_SSL_TIMEOUT_S) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=domain) as ssock:
                    # CERT_NONE gives empty dict for getpeercert(False) on most
                    # Python versions, but binary form is always available.
                    cert = ssock.getpeercert(binary_form=False) or {}
                    der = ssock.getpeercert(binary_form=True)
                    if not cert.get("issuer") and der:
                        cert = _parse_der_cert(der) or cert
        except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            raise _NoHTTPS(str(exc)) from exc
        except socket.timeout as exc:
            raise TimeoutError(f"SSL connection to {domain} timed out") from exc
        except Exception:
            pass

    if cert is None:
        return None

    cert["_valid"] = valid
    return cert


def _parse_der_cert(der: bytes) -> dict | None:
    """
    Best-effort parsing of a DER-encoded certificate using the cryptography
    library if available, otherwise return None.
    """
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        issuer_parts = {attr.oid._name: attr.value for attr in c.issuer}
        subject_parts = {attr.oid._name: attr.value for attr in c.subject}

        # Rebuild in Python ssl module tuple format
        issuer = tuple(
            ((k, v),) for k, v in issuer_parts.items()
        )
        subject = tuple(
            ((k, v),) for k, v in subject_parts.items()
        )

        # SANs
        san = ()
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = tuple(("DNS", name.value) for name in ext.value.get_values_for_type(x509.DNSName))
        except Exception:
            pass

        return {
            "issuer": issuer,
            "subject": subject,
            "notBefore": c.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": c.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": san,
        }
    except ImportError:
        logger.debug("cryptography library not available for DER cert parsing")
        return None
    except Exception as exc:
        logger.debug("DER cert parse failed: %s", exc)
        return None


def _check_validity(domain: str) -> bool:
    """Quick check: does the cert chain verify against the system trust store?"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=_SSL_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # If we get here without error, the cert is valid
                return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        # Network errors during the second connection — assume unknown
        return False


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _build_result(domain: str, cert: dict) -> dict:
    """Extract fields from a successfully retrieved certificate."""
    now = datetime.now(timezone.utc)

    issuer_dict = _dn_to_dict(cert.get("issuer", ()))
    subject_dict = _dn_to_dict(cert.get("subject", ()))

    issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or ""
    subject_org = subject_dict.get("organizationName") or ""
    subject_cn = subject_dict.get("commonName") or ""

    issued_on = _parse_cert_date(cert.get("notBefore"))
    expires_on = _parse_cert_date(cert.get("notAfter"))

    # Self-signed: issuer == subject (by comparing the full DN tuples)
    self_signed = _is_self_signed(cert.get("issuer", ()), cert.get("subject", ()))

    # Wildcard: CN or any SAN starts with *.
    wildcard = _is_wildcard(subject_cn, cert.get("subjectAltName", ()))

    valid = cert.get("_valid", False)

    # Derived numeric fields
    certificate_age_days = _days_between(issued_on, now) if issued_on else None
    days_until_expiry = _days_between(now, expires_on) if expires_on else None

    issuer_trust_tier = _lookup_issuer_trust(issuer_org)
    has_organization = 1 if subject_org.strip() else 0

    # Composite risk score
    risk_score = _compute_ssl_risk(
        self_signed=self_signed,
        valid=valid,
        certificate_age_days=certificate_age_days,
        issuer_trust_tier=issuer_trust_tier,
    )

    return {
        "domain": domain,
        "ssl_exists": True,
        "issuer": issuer_org or None,
        "issued_on": _fmt_date(issued_on),
        "expires_on": _fmt_date(expires_on),
        "certificate_age_days": certificate_age_days,
        "days_until_expiry": days_until_expiry,
        "self_signed": self_signed,
        "subject_organization": subject_org or None,
        "has_organization": has_organization,
        "wildcard": wildcard,
        "valid": valid,
        "issuer_trust_tier": issuer_trust_tier,
        "risk_score": risk_score,
        "lookup_failed": False,
    }


def _no_https_result(domain: str) -> dict:
    """Result for domains that don't serve HTTPS at all."""
    return {
        "domain": domain,
        "ssl_exists": False,
        "issuer": None,
        "issued_on": None,
        "expires_on": None,
        "certificate_age_days": None,
        "days_until_expiry": None,
        "self_signed": False,
        "subject_organization": None,
        "has_organization": 0,
        "wildcard": False,
        "valid": False,
        "issuer_trust_tier": DEFAULT_UNKNOWN_ISSUER_RISK,
        # HTTP-only is suspicious but not as strong a signal as a bad cert.
        # Fixed moderate-high contribution.
        "risk_score": 35,
        "lookup_failed": False,
    }


def _default_result(domain: str, *, reason: str = "unknown") -> dict:
    """Safe fallback when SSL lookup fails or times out."""
    return {
        "domain": domain,
        "ssl_exists": None,   # unknown
        "issuer": None,
        "issued_on": None,
        "expires_on": None,
        "certificate_age_days": None,
        "days_until_expiry": None,
        "self_signed": False,
        "subject_organization": None,
        "has_organization": 0,
        "wildcard": False,
        "valid": False,
        "issuer_trust_tier": DEFAULT_UNKNOWN_ISSUER_RISK,
        "risk_score": 30,    # neutral-ish default when unknown
        "lookup_failed": True,
        "lookup_failed_reason": reason,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dn_to_dict(dn_tuple: tuple) -> dict:
    """Convert a certificate DN tuple-of-tuples to a flat dict."""
    result = {}
    if not dn_tuple:
        return result
    for rdn in dn_tuple:
        if isinstance(rdn, tuple):
            for attr_type, attr_value in rdn:
                result[attr_type] = attr_value
    return result


def _parse_cert_date(date_str: str | None) -> datetime | None:
    """Parse certificate date strings (OpenSSL format)."""
    if not date_str:
        return None
    # Python's ssl module returns dates in '%b %d %H:%M:%S %Y GMT' format
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y %Z",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue
    return None


def _is_self_signed(issuer_dn: tuple, subject_dn: tuple) -> bool:
    """True if issuer DN == subject DN (self-signed certificate)."""
    if not issuer_dn or not subject_dn:
        return False
    return issuer_dn == subject_dn


def _is_wildcard(cn: str, san_tuple: tuple) -> bool:
    """True if the CN or any SAN starts with '*.'."""
    if cn.startswith("*."):
        return True
    for entry in san_tuple:
        if isinstance(entry, tuple) and len(entry) == 2:
            if str(entry[1]).startswith("*."):
                return True
    return False


def _days_between(start: datetime | None, end: datetime | None) -> int | None:
    """Days between two datetimes. Returns None if either is missing."""
    if start is None or end is None:
        return None
    delta = end - start
    return int(delta.total_seconds() / 86400)


def _fmt_date(dt: datetime | None) -> str | None:
    """Format datetime as ISO date string for JSON."""
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%d")


def _lookup_issuer_trust(issuer: str | None) -> float:
    """Return 0–1 risk tier for the certificate issuer."""
    if not issuer:
        return DEFAULT_UNKNOWN_ISSUER_RISK
    issuer_lower = issuer.lower().strip()
    # Exact match
    if issuer_lower in ISSUER_TRUST_TIER:
        return ISSUER_TRUST_TIER[issuer_lower]
    # Substring match — check if any known issuer name is contained
    for key, tier in ISSUER_TRUST_TIER.items():
        if key in issuer_lower or issuer_lower in key:
            return tier
    return DEFAULT_UNKNOWN_ISSUER_RISK


def _compute_ssl_risk(
    *,
    self_signed: bool,
    valid: bool,
    certificate_age_days: int | None,
    issuer_trust_tier: float,
) -> int:
    """
    SSL composite risk score (0–100, capped).

    Scoring formula per spec:
      +20  if self_signed
      +25  if not valid (expired or chain fails)
      +15  if certificate_age_days < 7
      +10  if issuer is unknown (issuer_trust_tier >= 0.7)
      -5   if issuer is a trusted CA (issuer_trust_tier <= 0.1)
    """
    score = 0

    if self_signed:
        score += 20

    if not valid:
        score += 25

    if certificate_age_days is not None and certificate_age_days < 7:
        score += 15

    if issuer_trust_tier >= 0.7:
        score += 10

    if issuer_trust_tier <= 0.1:
        score -= 5

    return max(0, min(score, 100))
