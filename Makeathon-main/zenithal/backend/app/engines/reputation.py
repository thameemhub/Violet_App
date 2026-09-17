"""
Zenithal — domain reputation (allowlist + blocklist).

The most reliable anti-phishing signal. A URL on a well-established domain is
safe regardless of how unusual its path/query is (Google search, ChatGPT
sessions, JWT tokens...); a URL whose exact host is on a live threat feed is
malicious regardless of how clean it looks.

Lists are built by training/build_reputation.py:
  allowlist_domains.txt  — top reputable registered domains (minus shorteners /
                           public-hosting platforms)
  blocklist_hosts.txt    — exact malicious hostnames (URLhaus)

Lookups are O(1) set membership. Loaded once at import.
"""

from app import config

_ALLOW: set[str] = set()
_BLOCK: set[str] = set()


def _load(path) -> set[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except Exception:
        return set()


_ALLOW = _load(config.ALLOWLIST_PATH)
_BLOCK = _load(config.BLOCKLIST_PATH)


def is_allowlisted(registered_domain: str | None) -> bool:
    """True if the registered domain is a well-established reputable site."""
    return bool(registered_domain) and registered_domain.lower() in _ALLOW


def is_blocklisted(hostname: str | None) -> bool:
    """True if the exact hostname is on the malicious-host feed."""
    return bool(hostname) and hostname.lower() in _BLOCK


def stats() -> dict:
    return {"allowlist": len(_ALLOW), "blocklist": len(_BLOCK)}
