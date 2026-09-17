"""
Zenithal — build domain reputation lists (allowlist + blocklist).

Domain reputation is the single most reliable anti-phishing signal (this is
what Google Safe Browsing / Microsoft SmartScreen lean on). A URL on a well-
established domain is safe no matter how weird its path/query looks.

Outputs (into data/):
  allowlist_domains.txt  — top reputable registered domains (Majestic), MINUS
                           URL shorteners and public-hosting platforms (where
                           anyone, including attackers, can host a subdomain).
  blocklist_hosts.txt    — exact malicious hostnames from URLhaus.

Run:  python training/build_reputation.py
"""

import os
from urllib.parse import urlparse

import pandas as pd

DATA = os.path.join(os.path.dirname(__file__), "data")          # feeds live here
OUT = os.path.join(os.path.dirname(__file__), "..", "data")     # runtime lookup dir
TOP_N = 1_000_000

# Shorteners hide the destination -> never auto-trust; let them go to analysis.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "lnkd.in", "db.tt", "qr.ae", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "tiny.cc", "bit.do", "soo.gd",
}
# Public-hosting / user-content platforms: the registered domain is legit infra
# but subdomains are attacker-controllable, so don't auto-trust the whole domain.
PUBLIC_HOSTING = {
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "wix.com",
    "github.io", "gitlab.io", "glitch.me", "herokuapp.com", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "r2.dev", "netlify.app",
    "vercel.app", "surge.sh", "000webhostapp.com", "repl.co", "replit.dev",
    "azurewebsites.net", "cloudfront.net", "amazonaws.com", "googleusercontent.com",
    "sharepoint.com", "onedrive.live.com", "dropbox.com", "drive.google.com",
    "sites.google.com", "notion.site", "webflow.io", "square.site", "godaddysites.com",
}
EXCLUDE = SHORTENERS | PUBLIC_HOSTING


def build_allowlist():
    path = os.path.join(DATA, "majestic.csv")
    if not os.path.exists(path):
        print("[!] majestic.csv missing — run update_feeds.py first.")
        return
    domains = pd.read_csv(path)["Domain"].dropna().astype(str).head(TOP_N)
    keep = [d for d in domains if d.lower() not in EXCLUDE]
    out = os.path.join(OUT, "allowlist_domains.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(keep))
    print(f"[OK] allowlist_domains.txt: {len(keep)} domains (excluded {len(domains)-len(keep)})")


def _urls_from_feeds() -> list[str]:
    """Collect malicious URLs from every available feed (all optional)."""
    urls: list[str] = []
    # URLhaus (malware) — CSV, url in 3rd column
    uh = os.path.join(DATA, "urlhaus_recent.csv")
    if os.path.exists(uh):
        s = pd.read_csv(uh, comment="#", header=None, quotechar='"',
                        names=list("abcdefghi"))["c"].dropna().astype(str)
        urls += s.tolist()
        print(f"    URLhaus: {len(s)}")
    # OpenPhish (phishing) — plain text, one URL per line
    op = os.path.join(DATA, "openphish.txt")
    if os.path.exists(op):
        with open(op, encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip().startswith("http")]
        urls += lines
        print(f"    OpenPhish: {len(lines)}")
    # PhishTank (verified phishing) — CSV with a 'url' column
    pt = os.path.join(DATA, "phishtank.csv")
    if os.path.exists(pt):
        try:
            df = pd.read_csv(pt, usecols=["url"])["url"].dropna().astype(str)
            urls += df.tolist()
            print(f"    PhishTank: {len(df)}")
        except Exception as e:
            print(f"    PhishTank skipped: {e}")
    return urls


def build_blocklist():
    urls = _urls_from_feeds()
    if not urls:
        print("[!] no threat feeds found — run update_feeds.py first.")
        return
    # Drop hosts whose registered domain is reputable (feeds list redirect-abuse
    # URLs on legit hosts like google.com/url?q=...; blocklisting those would
    # over-block the whole reputable domain).
    import tldextract
    allow = set()
    alp = os.path.join(OUT, "allowlist_domains.txt")
    if os.path.exists(alp):
        with open(alp, encoding="utf-8") as f:
            allow = {l.strip().lower() for l in f if l.strip()}

    hosts = set()
    for u in urls:
        try:
            h = (urlparse(u).hostname or "").lower()
            if not h:
                continue
            reg = tldextract.extract(h).registered_domain.lower()
            if reg and reg in allow:
                continue  # abuse-of-legit-host, not a malicious domain
            hosts.add(h)
        except Exception:
            pass
    out = os.path.join(OUT, "blocklist_hosts.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(hosts)))
    print(f"[OK] blocklist_hosts.txt: {len(hosts)} malicious hosts (from {len(urls)} feed URLs)")


if __name__ == "__main__":
    build_allowlist()
    build_blocklist()
