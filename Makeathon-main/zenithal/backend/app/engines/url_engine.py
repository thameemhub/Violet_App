"""
Zenithal — Engine 1: Phishing / Malicious URL detection.

Combines the XGBoost lexical classifier (with a heuristic fallback when no
model is trained yet) with IP intelligence + IP-domain correlation + WHOIS
intelligence + SSL certificate intelligence, then hands the fused signals
to the explainability layer.
"""

import json
import logging
from urllib.parse import urlparse

import joblib
import numpy as np
import tldextract

from app import config
from app.engines import ip_intel, reputation
from app.engines.explain import explain_url
from app.engines.ssl_engine import get_ssl_intelligence
from app.engines.whois_engine import get_whois_intelligence
from app.ml.features_url import FEATURE_NAMES, extract_url_features
from app.ml.features_ssl import extract_ssl_features
from app.ml.features_whois import extract_whois_features

logger = logging.getLogger("zenithal.url_engine")

# Concrete brand names an attacker impersonates (excludes generic words like
# 'login'/'secure'/'account' so a plain dev server isn't mistaken for a fake
# brand page). Used only for the loopback/private-IP safety check.
_REAL_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix",
    "instagram", "whatsapp", "linkedin", "twitter", "dropbox", "hdfc", "sbi",
    "icici", "axisbank", "citibank", "chase", "paytm", "irctc", "incometax",
    "flipkart", "dhl", "fedex", "amazonpay", "phonepe", "kotak",
]


class URLEngine:
    def __init__(self) -> None:
        self._model = None
        self._feature_names = FEATURE_NAMES
        self.loaded = False

    def load(self) -> None:
        if config.URL_MODEL_PATH.exists():
            try:
                self._model = joblib.load(config.URL_MODEL_PATH)
                if config.URL_FEATURE_NAMES_PATH.exists():
                    self._feature_names = json.loads(
                        config.URL_FEATURE_NAMES_PATH.read_text()
                    )
                self.loaded = True
            except Exception:
                self._model = None
                self.loaded = False

    # -- ML / heuristic scoring -------------------------------------------
    def _ml_score(self, features: dict[str, float]) -> float:
        vec = np.array([[features.get(n, 0.0) for n in self._feature_names]])
        proba = self._model.predict_proba(vec)[0][1]
        return round(float(proba) * 100, 2)

    def _heuristic_score(self, features: dict[str, float]) -> float:
        score = 0.0
        score += features.get("tld_risk_score", 0) * 20
        if features.get("has_brand_keyword", 0) > 0:
            score += 15
        if features.get("is_https", 0) == 0:
            score += 10
        score += min(features.get("suspicious_word_count", 0) * 5, 20)
        if features.get("has_ip_address", 0) > 0:
            score += 20
        if features.get("entropy", 0) > 4.0:
            score += 10
        if features.get("url_length", 0) > 100:
            score += 5
        if features.get("is_shortened_url", 0) > 0:
            score += 15
        if features.get("has_login_keyword", 0) > 0:
            score += 10
        if features.get("has_verify_keyword", 0) > 0:
            score += 10
        return min(score, 100.0)

    # -- Public API -------------------------------------------------------
    def analyze(self, url: str, with_ip_intel: bool = True,
                community_score: float | None = None,
                return_breakdown: bool = False) -> dict:
        features = extract_url_features(url)
        domain = _registered_domain(url)
        hostname = _hostname(url)

        # --- WHOIS intelligence (runs for every URL; cached internally) ---
        whois_data = _safe_whois(domain)
        whois_features = extract_whois_features(whois_data)
        whois_score = whois_data.get("risk_score", 50)

        # --- SSL certificate intelligence ---
        ssl_data = _safe_ssl(hostname or domain)
        ssl_features = extract_ssl_features(ssl_data)
        ssl_score = ssl_data.get("risk_score", 30)

        # === Decision order: reputation first, ML only for unknown domains ===
        if reputation.is_allowlisted(domain):
            corr = self._correlate(domain, with_ip_intel)
            reasons = [f"'{domain}' is a well-established, reputable domain (global top-1M). "
                       "A legitimate site's path or query does not make it malicious."] + corr["signals"]
            res = self._result(url, features, 2.0, 0.0, corr, "reputation-allowlist",
                                 reasons, "No threat detected", whois_data, ssl_data)
            if return_breakdown:
                res["breakdown"] = {"lexical_score": 0.0, "whois_score": whois_score, "ssl_score": ssl_score, "ip_risk": corr["ip_risk"], "community_score": community_score}
            return res

        if reputation.is_blocklisted(hostname):
            corr = self._correlate(domain, with_ip_intel)
            reasons = ["Host is on an active malicious-URL threat feed (URLhaus) - known to distribute malware/phishing."] + corr["signals"]
            res = self._result(url, features, 100.0, 100.0, corr, "blocklist",
                                 reasons, "Known Malicious Host", whois_data, ssl_data)
            if return_breakdown:
                res["breakdown"] = {"lexical_score": 100.0, "whois_score": whois_score, "ssl_score": ssl_score, "ip_risk": corr["ip_risk"], "community_score": community_score}
            return res

        if self._model is not None:
            try:
                lexical_score = self._ml_score(features)
                model_used = "xgboost"
            except Exception:
                logger.warning("ML model predict failed, falling back to heuristic")
                lexical_score = self._heuristic_score(features)
                model_used = "heuristic"
        else:
            lexical_score = self._heuristic_score(features)
            model_used = "heuristic"

        corr = self._correlate(domain, with_ip_intel)

        # --- Weighted fusion (4 active signals) ---
        ip_risk_norm = min(corr["ip_risk"] * 2.5, 100.0)
        fuse_res = _fuse_scores(lexical_score, whois_score, ssl_score, ip_risk_norm,
                                community_score=community_score, return_breakdown=return_breakdown)
        
        if return_breakdown:
            fused, breakdown = fuse_res
        else:
            fused = fuse_res
            breakdown = None

        # Loopback / private hosts are local/dev resources, not phishing —
        # unless they serve a fake brand page (192.168.1.1/paypal/login).
        if _is_local_host(url):
            if not any(b in url.lower() for b in _REAL_BRANDS):
                fused = min(fused, 10.0)
                corr = {**corr, "signals": ["Loopback/private address - local or internal resource, not a public phishing site."]}

        reasons, threat_type = explain_url(url, features, corr, lexical_score,
                                           whois_data=whois_data,
                                           ssl_data=ssl_data)
        verdict = config.score_to_verdict(fused)
        if verdict == "SAFE":
            threat_type = "No threat detected"
            
        res = self._result(url, features, fused, lexical_score, corr, model_used,
                            reasons, threat_type, whois_data, ssl_data)
        if return_breakdown and breakdown is not None:
            res["breakdown"] = breakdown
        return res

    def _correlate(self, domain: str | None, with_ip_intel: bool) -> dict:
        corr = {"resolved_ip": None, "intel": None, "signals": [], "ip_risk": 0.0}
        if with_ip_intel and domain:
            try:
                corr = ip_intel.correlate_domain(domain)
            except Exception:
                pass
        return corr

    def _result(self, url, features, fused, lexical_score, corr, model_used,
                reasons, threat_type, whois_data=None, ssl_data=None) -> dict:
        result = {
            "channel": "url",
            "input": url,
            "score": round(fused, 1),
            "lexical_score": round(lexical_score, 1),
            "ip_risk": round(corr["ip_risk"], 1),
            "verdict": config.score_to_verdict(fused),
            "threat_type": threat_type,
            "model_used": model_used,
            "resolved_ip": corr["resolved_ip"],
            "ip_intel": corr["intel"],
            "reasons": reasons,
            "top_features": _top_features(features),
        }
        # --- WHOIS intelligence block (extends existing response) ---
        if whois_data is not None:
            result["whois_intelligence"] = {
                "domain": whois_data.get("domain"),
                "creation_date": whois_data.get("creation_date"),
                "expiration_date": whois_data.get("expiration_date"),
                "updated_date": whois_data.get("updated_date"),
                "registrar": whois_data.get("registrar"),
                "registrant_org": whois_data.get("registrant_org"),
                "registrant_name": whois_data.get("registrant_name"),
                "domain_age_days": whois_data.get("domain_age_days"),
                "privacy_enabled": whois_data.get("privacy_enabled", False),
                "country": whois_data.get("country"),
                "status": whois_data.get("status", []),
                "risk_score": whois_data.get("risk_score", 50),
                "lookup_failed": whois_data.get("lookup_failed", True),
            }
        # --- SSL intelligence block (extends existing response) ---
        if ssl_data is not None:
            result["ssl_intelligence"] = {
                "domain": ssl_data.get("domain"),
                "ssl_exists": ssl_data.get("ssl_exists"),
                "issuer": ssl_data.get("issuer"),
                "issued_on": ssl_data.get("issued_on"),
                "expires_on": ssl_data.get("expires_on"),
                "certificate_age_days": ssl_data.get("certificate_age_days"),
                "days_until_expiry": ssl_data.get("days_until_expiry"),
                "self_signed": ssl_data.get("self_signed", False),
                "subject_organization": ssl_data.get("subject_organization"),
                "wildcard": ssl_data.get("wildcard", False),
                "valid": ssl_data.get("valid", False),
                "risk_score": ssl_data.get("risk_score", 30),
                "lookup_failed": ssl_data.get("lookup_failed", True),
            }
        return result


def _is_local_host(url: str) -> bool:
    """True if the URL host is localhost or a private/loopback IP."""
    import ipaddress
    try:
        if "://" not in url:
            url = "http://" + url
        host = urlparse(url).hostname or ""
        if host in ("localhost", "localhost.localdomain"):
            return True
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return False


def _registered_domain(url: str) -> str | None:
    try:
        if "://" not in url:
            url = "http://" + url
        ext = tldextract.extract(url)
        return ext.registered_domain or urlparse(url).netloc or None
    except Exception:
        return None


def _hostname(url: str) -> str | None:
    """Full host (including subdomain), for exact blocklist matching."""
    try:
        if "://" not in url:
            url = "http://" + url
        return (urlparse(url).hostname or "").lower() or None
    except Exception:
        return None


def _top_features(features: dict[str, float]) -> dict[str, float]:
    """A few human-interesting features for the UI."""
    keys = [
        "url_length", "num_subdomains", "tld_risk_score", "has_ip_address",
        "has_brand_keyword", "is_https", "is_shortened_url", "suspicious_word_count",
        "entropy",
    ]
    return {k: round(features.get(k, 0.0), 3) for k in keys}


def _safe_whois(domain: str | None) -> dict:
    """Run WHOIS lookup with full error isolation."""
    if not domain:
        return get_whois_intelligence("")
    try:
        return get_whois_intelligence(domain)
    except Exception as exc:
        logger.debug("WHOIS intelligence failed for %s: %s", domain, exc)
        return get_whois_intelligence("")  # returns safe default


def _safe_ssl(domain: str | None) -> dict:
    """Run SSL certificate lookup with full error isolation."""
    if not domain:
        return get_ssl_intelligence("")
    try:
        return get_ssl_intelligence(domain)
    except Exception as exc:
        logger.debug("SSL intelligence failed for %s: %s", domain, exc)
        return get_ssl_intelligence("")  # returns safe default


def _fuse_scores(ml_score: float, whois_score: float, ssl_score: float,
                 ip_risk_norm: float,
                 community_score: float | None = None,
                 return_breakdown: bool = False):
    """
    Weighted fusion of all active threat signals.
    """
    breakdown = {
        "lexical_score": ml_score,
        "whois_score": whois_score,
        "ssl_score": ssl_score,
        "ip_risk": ip_risk_norm,
        "community_score": community_score
    }
    if community_score is not None:
        fused = (
            0.40 * ml_score
            + 0.20 * whois_score
            + 0.10 * ssl_score
            + 0.15 * community_score
            + 0.15 * ip_risk_norm
        )
    else:
        fused = (
            0.50 * ml_score
            + 0.20 * whois_score
            + 0.10 * ssl_score
            + 0.20 * ip_risk_norm
        )
    final_score = min(fused, 100.0)
    if return_breakdown:
        return final_score, breakdown
    return final_score


# Module-level singleton, loaded at app startup.
engine = URLEngine()
