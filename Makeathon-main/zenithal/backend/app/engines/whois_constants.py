"""
Zenithal — WHOIS intelligence constants.

Lookup tables and detection strings for the WHOIS engine. These are starter
heuristics and should be calibrated against real-world distribution data.
Do NOT treat these as final — they are baseline values for demo/MVP use.
"""

# ---------------------------------------------------------------------------
# Privacy / proxy service detection strings
# ---------------------------------------------------------------------------
# WHOIS registrant fields containing any of these (case-insensitive) indicate
# the domain owner is using a privacy/proxy service.  This is not inherently
# malicious, but it removes one verification path.
PRIVACY_SERVICE_KEYWORDS: list[str] = [
    "whoisguard",
    "privacy protect",
    "redacted for privacy",
    "domains by proxy",
    "contact privacy inc",
    "perfectprivacy",
    "withheldforprivacy",
    "data protected",
    "identity protection",
    "whoisprivacyprotect",
    "privacydotlink",
    "super privacy",
    "domain privacy",
    "gdpr masked",
    "statutory masking",
    "private registration",
    "anonymize",
]

# ---------------------------------------------------------------------------
# Registrar reputation (starter heuristics — expand with real abuse data)
# ---------------------------------------------------------------------------
# Lower value = more reputable.  Keys MUST be lowercase, stripped of
# extraneous punctuation.  The lookup function normalizes query strings
# before matching.
REGISTRAR_REPUTATION: dict[str, float] = {
    "godaddy.com llc": 0.1,
    "godaddy": 0.1,
    "cloudflare inc": 0.1,
    "cloudflare": 0.1,
    "google llc": 0.1,
    "google": 0.1,
    "amazon registrar inc": 0.1,
    "markmonitor inc": 0.05,
    "markmonitor": 0.05,
    "namecheap inc": 0.2,
    "namecheap": 0.2,
    "tucows domains inc": 0.2,
    "tucows": 0.2,
    "name.com inc": 0.2,
    "gandi sas": 0.2,
    "ovh sas": 0.2,
    "ionos se": 0.25,
    "1&1 ionos": 0.25,
    "networksolutions llc": 0.2,
    "dynadot llc": 0.3,
    "enom llc": 0.3,
    "porkbun llc": 0.3,
    # --- Known cheap / bulk / abuse-prone registrars (starter) ---
    "freenom": 0.95,
    "hosting concepts bv": 0.85,
    "regru": 0.7,
    "eranet international": 0.8,
    "west263 international": 0.85,
    "nicenic international": 0.85,
    "alibaba cloud computing": 0.6,
}

DEFAULT_UNKNOWN_REGISTRAR_RISK: float = 0.8

# ---------------------------------------------------------------------------
# Country-of-registrant risk (starter heuristics)
# ---------------------------------------------------------------------------
# Higher value = higher risk.  Many ccTLDs do not return a country field;
# those resolve to the default.
COUNTRY_RISK: dict[str, float] = {
    "US": 0.1, "GB": 0.1, "DE": 0.1, "CA": 0.1, "AU": 0.1, "JP": 0.1,
    "FR": 0.15, "NL": 0.15, "SE": 0.1, "NO": 0.1, "CH": 0.1,
    "IN": 0.2, "BR": 0.25, "KR": 0.15, "SG": 0.1,
    "CN": 0.5, "RU": 0.6, "NG": 0.7, "RO": 0.5,
    "UA": 0.45, "PK": 0.5, "BD": 0.5, "VN": 0.4,
    "PA": 0.55, "BZ": 0.55,  # common offshore registrar jurisdictions
}

DEFAULT_UNKNOWN_COUNTRY_RISK: float = 0.4

# ---------------------------------------------------------------------------
# Suspicious WHOIS status codes (EPP status codes that indicate problems)
# ---------------------------------------------------------------------------
# These are non-standard or abusive states.  A domain with multiple hold /
# suspended statuses is more likely to be malicious or recently seized.
SUSPICIOUS_STATUS_CODES: list[str] = [
    "clienthold",
    "serverhold",
    "clienttransferprohibited",
    "servertransferprohibited",
    "clientupdateprohibited",
    "serverupdateprohibited",
    "pendingtransfer",
    "pendingdelete",
    "redemptionperiod",
    "inactive",
]
