"""
Zenithal  - Explainability layer.

Turns raw signals into ranked, plain-language reasons. This is what makes a
verdict trustworthy to a human analyst (and what SIH judges reward): every
decision says *why*, not just a score.
"""


def explain_url(url: str, features: dict, corr: dict, lexical_score: float,
                *, whois_data: dict | None = None,
                ssl_data: dict | None = None) -> tuple[list[str], str]:
    """Return (ordered reasons, threat_type) for a URL verdict."""
    reasons: list[str] = []

    # --- IP-data driven reasons come first (the PS differentiator) ---
    reasons.extend(corr.get("signals", []))

    # --- WHOIS-driven reasons ---
    if whois_data and not whois_data.get("lookup_failed"):
        age = whois_data.get("domain_age_days")
        if age is not None and age < 7:
            reasons.append(f"Domain registered only {age} day(s) ago — very recently created domains are a top phishing indicator.")
        elif age is not None and age < 30:
            reasons.append(f"Domain is only {age} days old — newly registered domains carry elevated risk.")

        if whois_data.get("privacy_enabled"):
            reasons.append("WHOIS registrant information is hidden behind a privacy/proxy service.")

        rep = whois_data.get("registrar_reputation", 0)
        if rep >= 0.8:
            registrar = whois_data.get("registrar") or "unknown"
            reasons.append(f"Registered through '{registrar}' — a low-reputation or unknown registrar.")

        update_days = whois_data.get("days_since_last_update")
        if update_days is not None and update_days < 7:
            reasons.append("Domain registration was updated in the last 7 days — may indicate recent hijacking or setup.")

        reg_period = whois_data.get("registration_period_days")
        if reg_period is not None and reg_period <= 365:
            reasons.append("Domain registered for 1 year or less — short registration periods are common for throwaway phishing sites.")

    # --- SSL certificate-driven reasons ---
    if ssl_data and not ssl_data.get("lookup_failed"):
        if ssl_data.get("self_signed"):
            reasons.append("The site uses a self-signed SSL certificate — not issued by any trusted Certificate Authority.")

        if ssl_data.get("ssl_exists") and not ssl_data.get("valid"):
            reasons.append("The SSL certificate is invalid (expired or fails chain verification) — a strong indicator of a suspicious or abandoned site.")

        cert_age = ssl_data.get("certificate_age_days")
        if cert_age is not None and cert_age < 7:
            reasons.append(f"SSL certificate was issued only {cert_age} day(s) ago — very fresh certificates are common on newly set-up phishing sites.")

        if ssl_data.get("ssl_exists") is False:
            reasons.append("The site does not serve HTTPS at all — credentials or data submitted here would travel unencrypted.")

        issuer_tier = ssl_data.get("issuer_trust_tier", 0.7)
        if issuer_tier >= 0.7:
            issuer_name = ssl_data.get("issuer") or "unknown"
            reasons.append(f"Certificate issued by '{issuer_name}' — an unrecognized or low-reputation Certificate Authority.")

    is_official = corr.get("is_official", False)

    # --- Lexical / structural reasons ---
    if features.get("has_ip_address", 0) > 0:
        reasons.append("URL uses a raw IP address instead of a domain name  - a common way to hide identity.")
    if features.get("has_brand_keyword", 0) > 0 and not is_official:
        reasons.append("Contains a trusted brand keyword (e.g. bank/paypal/sbi) in a non-official domain  - likely impersonation.")
    if features.get("is_subdomain_of_brand", 0) > 0 and not is_official:
        reasons.append("Brand name placed in the subdomain to look legitimate (e.g. sbi.secure-login.top).")
    if features.get("tld_risk_score", 0) >= 0.7:
        reasons.append("Registered on a high-abuse TLD (.tk/.top/.xyz etc.) frequently used for throwaway phishing sites.")
    if features.get("is_shortened_url", 0) > 0:
        reasons.append("A URL shortener hides the true destination until it is opened.")
    if features.get("is_https", 0) == 0 and lexical_score > 40:
        reasons.append("No HTTPS  - credentials submitted here would travel in clear text.")
    if features.get("suspicious_word_count", 0) >= 2:
        reasons.append("Multiple urgency/credential keywords (verify, urgent, suspended, login)  - classic social-engineering bait.")
    if features.get("entropy", 0) > 4.0:
        reasons.append("High-entropy (randomised) domain name  - typical of auto-generated malicious domains.")
    if features.get("has_encoded_chars", 0) > 0:
        reasons.append("Percent-encoded characters in the URL may be masking a redirect or payload.")
    if features.get("redirect_in_url", 0) > 0:
        reasons.append("An open-redirect parameter can bounce victims to an attacker-controlled page.")

    if not reasons:
        reasons.append("No strong risk indicators found. Structure and hosting look consistent with a legitimate site.")

    return reasons[:12], _url_threat_type(url, features, corr)


def _url_threat_type(url: str, features: dict, corr: dict) -> str:
    ul = url.lower()
    if corr.get("intel") and corr["intel"].get("reputation") == "malicious":
        return "Malicious Hosting"
    if features.get("has_brand_keyword", 0) > 0 or features.get("is_subdomain_of_brand", 0) > 0:
        return "Brand Impersonation"
    if features.get("has_login_keyword", 0) > 0 or "password" in ul:
        return "Credential Harvesting"
    if features.get("is_shortened_url", 0) > 0:
        return "Obfuscated URL"
    if features.get("has_ip_address", 0) > 0:
        return "Suspicious Infrastructure"
    if features.get("tld_risk_score", 0) >= 0.7:
        return "High-Risk Domain"
    return "General Phishing"


def explain_attacker(profile: dict) -> list[str]:
    """Plain-language summary for an attacker-IP profile (Engine 2)."""
    reasons: list[str] = []
    intel = profile.get("intel", {}) or {}
    types = profile.get("attack_types", {})
    total = profile.get("total_hits", 0)

    if types:
        mix = ", ".join(f"{v}× {k}" for k, v in sorted(types.items(), key=lambda x: -x[1]))
        reasons.append(f"{total} malicious requests from this IP: {mix}.")

    burst = profile.get("burst_seconds")
    if burst is not None and total >= 5:
        rate = total / max(burst, 1)
        if rate > 1:
            reasons.append(f"High-velocity activity: ~{rate:.1f} attack requests/second  - automated scanning, not a human.")

    if intel.get("reputation") == "malicious":
        reasons.append(f"Source network flagged malicious: {intel.get('org')} ({intel.get('country')}).")
    elif intel.get("hosting_type") in ("bulletproof", "tor"):
        reasons.append(f"Originates from {intel.get('hosting_type')} infrastructure ({intel.get('org')}).")

    if intel.get("country") and intel.get("country") not in ("Unknown", "Private Network"):
        reasons.append(f"Geolocated to {intel.get('city')}, {intel.get('country')} (ASN {intel.get('asn')}).")

    if len(types) >= 3:
        reasons.append("Multiple distinct attack techniques from one IP indicate a determined, tooled adversary.")

    return reasons
