"""
Zenithal  - URL Feature Extractor
Extracts 38 structural/lexical/host features from a raw URL for ML
classification. Zero-day capable: no domain history required.

Ported from the proven PhishGuard extractor; logging dependency removed so
this module is standalone.
"""

import math
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

import tldextract

# TLD risk scores  - higher = riskier
TLD_RISK_SCORES: dict[str, float] = {
    "tk": 1.0, "ml": 0.9, "ga": 0.9, "cf": 0.9, "gq": 0.9,
    "xyz": 0.8, "top": 0.8, "club": 0.7, "online": 0.7, "site": 0.7,
    "info": 0.6, "click": 0.6, "link": 0.6, "buzz": 0.6, "work": 0.6,
    "bid": 0.5, "trade": 0.5, "webcam": 0.5, "review": 0.5, "stream": 0.5,
    "net": 0.3, "org": 0.2, "edu": 0.05, "gov": 0.05,
    "com": 0.1, "co": 0.15, "io": 0.2, "dev": 0.15, "app": 0.15,
}

# Known brands for lookalike detection
BRAND_KEYWORDS: list[str] = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "linkedin", "twitter", "netflix", "dropbox", "instagram", "whatsapp",
    "bank", "secure", "login", "verify", "account", "update",
    "hdfc", "sbi", "icici", "citibank", "chase",
]

# URL shortener domains
SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "lnkd.in", "db.tt", "qr.ae", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy",
}

# Suspicious words in URLs
SUSPICIOUS_WORDS: list[str] = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "suspended",
    "urgent", "alert", "warning", "restore", "unlock", "validate",
    "authenticate", "identity", "support", "helpdesk",
]


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def has_ip_literal(url: str) -> bool:
    """True if the URL uses an IPv4 literal instead of a hostname."""
    return bool(re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}").match(url))


FEATURE_NAMES: list[str] = [
    # URL Structure (10)
    "url_length", "num_dots", "num_hyphens", "num_underscores",
    "num_slashes", "num_at_symbols", "num_digits", "digit_ratio",
    "has_ip_address", "num_subdomains",
    # Domain (8)
    "domain_length", "tld_risk_score", "entropy", "has_brand_keyword",
    "num_brand_keywords", "is_subdomain_of_brand", "has_consecutive_hyphens",
    "domain_digit_ratio",
    # Path/Query (8)
    "path_length", "num_path_segments", "query_length", "num_query_params",
    "has_login_keyword", "has_verify_keyword", "has_secure_keyword",
    "has_update_keyword",
    # Protocol (4)
    "is_https", "has_port", "port_number_risk", "redirect_in_url",
    # Lexical (8)
    "suspicious_word_count", "url_entropy", "ratio_special_chars",
    "is_shortened_url", "num_redirects_in_path", "has_encoded_chars",
    "path_entropy", "has_double_slash",
]


def extract_url_features(url: str) -> dict[str, float]:
    """Extract all 38 features from a URL. Returns zeros on parse failure."""
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        domain = extracted.registered_domain or parsed.netloc
        subdomain = extracted.subdomain
        tld = extracted.suffix
        path = parsed.path or ""
        query = parsed.query or ""

        f: dict[str, float] = {}

        # === URL Structure (10) ===
        f["url_length"] = float(len(url))
        f["num_dots"] = float(url.count("."))
        f["num_hyphens"] = float(url.count("-"))
        f["num_underscores"] = float(url.count("_"))
        f["num_slashes"] = float(url.count("/"))
        f["num_at_symbols"] = float(url.count("@"))
        f["num_digits"] = float(sum(c.isdigit() for c in url))
        f["digit_ratio"] = f["num_digits"] / len(url) if url else 0.0
        f["has_ip_address"] = 1.0 if has_ip_literal(url) else 0.0
        f["num_subdomains"] = float(len(subdomain.split(".")) if subdomain else 0)

        # === Domain (8) ===
        f["domain_length"] = float(len(domain))
        f["tld_risk_score"] = TLD_RISK_SCORES.get(tld.lower(), 0.3)
        f["entropy"] = _shannon_entropy(domain)
        brand_matches = [
            kw for kw in BRAND_KEYWORDS
            if kw in domain.lower() or kw in subdomain.lower()
        ]
        f["has_brand_keyword"] = 1.0 if brand_matches else 0.0
        f["num_brand_keywords"] = float(len(brand_matches))
        f["is_subdomain_of_brand"] = 1.0 if any(
            kw in subdomain.lower() for kw in BRAND_KEYWORDS
        ) else 0.0
        f["has_consecutive_hyphens"] = 1.0 if "--" in domain else 0.0
        domain_digits = sum(c.isdigit() for c in domain)
        f["domain_digit_ratio"] = domain_digits / len(domain) if domain else 0.0

        # === Path/Query (8) ===
        f["path_length"] = float(len(path))
        f["num_path_segments"] = float(len([s for s in path.split("/") if s]))
        f["query_length"] = float(len(query))
        f["num_query_params"] = float(len(parse_qs(query)))
        pl = path.lower()
        f["has_login_keyword"] = 1.0 if ("login" in pl or "signin" in pl) else 0.0
        f["has_verify_keyword"] = 1.0 if ("verify" in pl or "confirm" in pl) else 0.0
        f["has_secure_keyword"] = 1.0 if ("secure" in pl or "security" in pl) else 0.0
        f["has_update_keyword"] = 1.0 if ("update" in pl or "upgrade" in pl) else 0.0

        # === Protocol (4) ===
        f["is_https"] = 1.0 if parsed.scheme == "https" else 0.0
        f["has_port"] = 1.0 if parsed.port else 0.0
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        f["port_number_risk"] = 1.0 if port not in (80, 443, 8080, 8443) else 0.0
        f["redirect_in_url"] = 1.0 if (
            "redirect" in url.lower() or "url=" in url.lower() or "next=" in url.lower()
        ) else 0.0

        # === Lexical (8) ===
        f["suspicious_word_count"] = float(
            sum(1 for w in SUSPICIOUS_WORDS if w in url.lower())
        )
        f["url_entropy"] = _shannon_entropy(url)
        special = sum(1 for c in url if not c.isalnum() and c not in "/:.")
        f["ratio_special_chars"] = special / len(url) if url else 0.0
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        f["is_shortened_url"] = 1.0 if full_domain.lower() in SHORTENER_DOMAINS else 0.0
        f["num_redirects_in_path"] = float(
            path.lower().count("redirect") + path.lower().count("redir")
        )
        f["has_encoded_chars"] = 1.0 if "%" in url else 0.0
        f["path_entropy"] = _shannon_entropy(path)
        f["has_double_slash"] = 1.0 if "//" in path else 0.0

        return f
    except Exception:
        return {name: 0.0 for name in FEATURE_NAMES}
