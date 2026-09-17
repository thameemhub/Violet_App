"""
Zenithal  - IP Intelligence  (the "from IP Data" core of SIH25229)

For any IP or domain this module produces:
  - Geolocation (country, city, lat/lon)         -> powers the SOC world map
  - ASN + hosting organisation                    -> who owns the address space
  - Hosting classification (bulletproof/tor/...)   -> infrastructure risk
  - Reputation (malicious/suspicious/clean)        -> threat feeds
  - Reverse DNS (PTR)                              -> sanity/consistency check
  - IP<->domain correlation                        -> brand geo mismatch etc.

Backends, tried in order:
  1. MaxMind GeoLite2 (if backend/data/*.mmdb present)  -> live, real data
  2. Bundled offline reference table                    -> demo-safe, no signup
  3. Deterministic hash fallback                        -> any public IP still
     gets a stable, plausible pin so the map is never empty
"""

import ipaddress
import json
import socket
from functools import lru_cache

from app import config

# --- Optional geoip2 backend ---------------------------------------------
try:
    import geoip2.database  # type: ignore
    _HAS_GEOIP2 = True
except Exception:
    _HAS_GEOIP2 = False

# --- Load bundled reference ----------------------------------------------
try:
    with open(config.IP_REFERENCE_PATH, "r", encoding="utf-8") as fh:
        _REF = json.load(fh)
except Exception:
    _REF = {"known_ips": {}, "country_fallback": {}, "brand_expected_geo": {}}

_KNOWN_IPS: dict = _REF.get("known_ips", {})
_COUNTRY_FALLBACK: dict = _REF.get("country_fallback", {})
_BRAND_GEO: dict = _REF.get("brand_expected_geo", {})

# Bulletproof / abuse-prone ASNs (small curated list for demo credibility)
_BAD_ASNS: set[int] = {204957, 205100, 49505, 209160, 44477, 60781}

_geoip_city_reader = None
_geoip_asn_reader = None
if _HAS_GEOIP2:
    try:
        if config.GEOIP_CITY_DB.exists():
            _geoip_city_reader = geoip2.database.Reader(str(config.GEOIP_CITY_DB))
        if config.GEOIP_ASN_DB.exists():
            _geoip_asn_reader = geoip2.database.Reader(str(config.GEOIP_ASN_DB))
    except Exception:
        _geoip_city_reader = _geoip_asn_reader = None


def _fallback_country_code(ip: str) -> str:
    """Deterministically pick a country for an unknown public IP so the map
    always has a stable pin. Clearly a heuristic  - real data comes from
    GeoLite2 when installed."""
    codes = list(_COUNTRY_FALLBACK.keys()) or ["US"]
    h = int(ipaddress.ip_address(ip)) if _is_ip(ip) else abs(hash(ip))
    return codes[h % len(codes)]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def resolve_domain(domain: str) -> str | None:
    """Resolve a hostname to an IPv4 address (best effort, cached)."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


@lru_cache(maxsize=4096)
def reverse_dns(ip: str) -> str | None:
    """PTR lookup (best effort, cached)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


@lru_cache(maxsize=4096)
def lookup_ip(ip: str) -> dict:
    """Return the full intelligence record for a single IP."""
    if not _is_ip(ip):
        return _empty(ip)

    if _is_private(ip):
        return {
            "ip": ip, "country": "Private Network", "country_code": "--",
            "city": "LAN", "lat": 0.0, "lon": 0.0, "asn": 0,
            "org": "RFC1918 private address", "hosting_type": "private",
            "reputation": "internal", "source": "local",
        }

    # 1) Curated known IPs (demo attackers)
    if ip in _KNOWN_IPS:
        rec = dict(_KNOWN_IPS[ip])
        rec.update({"ip": ip, "source": "reference"})
        return rec

    # 2) MaxMind GeoLite2 if available
    if _geoip_city_reader is not None:
        try:
            city = _geoip_city_reader.city(ip)
            asn_num, asn_org = 0, "unknown"
            if _geoip_asn_reader is not None:
                a = _geoip_asn_reader.asn(ip)
                asn_num = a.autonomous_system_number or 0
                asn_org = a.autonomous_system_organization or "unknown"
            return {
                "ip": ip,
                "country": city.country.name or "Unknown",
                "country_code": city.country.iso_code or "--",
                "city": city.city.name or "Unknown",
                "lat": float(city.location.latitude or 0.0),
                "lon": float(city.location.longitude or 0.0),
                "asn": asn_num,
                "org": asn_org,
                "hosting_type": "bulletproof" if asn_num in _BAD_ASNS else "hosting",
                "reputation": "malicious" if asn_num in _BAD_ASNS else "unknown",
                "source": "geolite2",
            }
        except Exception:
            pass

    # 3) Deterministic offline fallback
    cc = _fallback_country_code(ip)
    geo = _COUNTRY_FALLBACK.get(cc, {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0})
    return {
        "ip": ip,
        "country": geo["country"], "country_code": cc, "city": geo["city"],
        "lat": geo["lat"], "lon": geo["lon"],
        "asn": 0, "org": "Unknown network", "hosting_type": "unknown",
        "reputation": "unknown", "source": "heuristic",
    }


def _empty(value: str) -> dict:
    return {
        "ip": value, "country": "Unknown", "country_code": "--", "city": "Unknown",
        "lat": 0.0, "lon": 0.0, "asn": 0, "org": "Unknown", "hosting_type": "unknown",
        "reputation": "unknown", "source": "none",
    }


def correlate_domain(url_domain: str) -> dict:
    """
    IP<->domain correlation for a phishing/malicious-URL verdict.
    Resolves the domain, geolocates the hosting IP, and flags mismatches
    between the *brand implied by the domain* and *where it is actually
    hosted*  - the classic tell of a phishing site.

    Returns intel + correlation signals + a 0-40 IP risk contribution.
    """
    ip = resolve_domain(url_domain)
    signals: list[str] = []
    ip_risk = 0.0

    if ip is None:
        signals.append("Domain does not resolve to any IP (dead/parked or newly registered).")
        return {"resolved_ip": None, "intel": None, "signals": signals, "ip_risk": 15.0,
                "is_official": url_domain.lower() in _BRAND_GEO}

    intel = lookup_ip(ip)
    ptr = reverse_dns(ip)
    intel["reverse_dns"] = ptr

    # Reputation of hosting infra
    if intel.get("reputation") == "malicious":
        ip_risk += 30
        signals.append(f"Hosted on known-malicious infrastructure: {intel['org']} ({intel['country']}).")
    elif intel.get("hosting_type") in ("bulletproof", "tor"):
        ip_risk += 25
        signals.append(f"Hosted on {intel['hosting_type']} infrastructure ({intel['org']}).")
    elif intel.get("reputation") == "suspicious":
        ip_risk += 12
        signals.append(f"Hosted on abuse-prone network: {intel['org']} ({intel['country']}).")

    # Brand geo mismatch  - the money signal.
    # Only fire for LOOKALIKE domains (brand root embedded but NOT the official
    # domain), and only when the geolocation is RELIABLE (curated reference or
    # GeoLite2). The deterministic hash fallback ('heuristic') is never used to
    # assert a mismatch, so a legit brand site is never falsely flagged.
    is_official = url_domain.lower() in _BRAND_GEO
    expected_cc = _brand_expected_cc(url_domain)
    if (
        expected_cc
        and not is_official
        and intel.get("source") in ("reference", "geolite2")
        and intel.get("country_code") not in (expected_cc, "--")
    ):
        ip_risk += 20
        signals.append(
            f"IP-domain mismatch: '{url_domain}' mimics a brand expected in "
            f"{expected_cc}, but is hosted in {intel['country']} "
            f"({intel['country_code']}). Legitimate sites are not hosted here."
        )

    # NOTE: We deliberately do NOT flag "reverse DNS does not match" — legit
    # sites are almost always behind CDNs/clouds (1e100.net, googleusercontent,
    # cloudfront) whose PTR never matches the served domain, so that check is
    # pure noise. The PTR is kept in `intel["reverse_dns"]` for information only.

    return {
        "resolved_ip": ip,
        "intel": intel,
        "signals": signals,
        "ip_risk": min(ip_risk, 40.0),
        "is_official": is_official,
    }


def _brand_expected_cc(domain: str) -> str | None:
    """If the domain *looks like* it impersonates a known brand, return the
    country code that brand should be hosted in."""
    d = domain.lower()
    # exact brand domain
    if d in _BRAND_GEO:
        return _BRAND_GEO[d]
    # brand keyword embedded in a lookalike domain (e.g. sbi-verify.top)
    for brand, cc in _BRAND_GEO.items():
        root = brand.split(".")[0]
        if root in d and d != brand:
            return cc
    return None


def geo_backend() -> str:
    """Report which geolocation backend is active (for /health)."""
    if _geoip_city_reader is not None:
        return "geolite2"
    return "offline-reference"
