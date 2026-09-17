"""
Shared test fixtures for Zenithal backend tests.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pytest

# Ensure the backend app package is importable from tests/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def old_domain_whois():
    """Simulated WHOIS response for a well-established domain (google.com)."""
    now = datetime.now(timezone.utc)
    return type("WhoisResult", (), {
        "domain_name": "GOOGLE.COM",
        "creation_date": now - timedelta(days=9000),
        "expiration_date": now + timedelta(days=3650),
        "updated_date": now - timedelta(days=90),
        "registrar": "MarkMonitor Inc.",
        "org": "Google LLC",
        "name": "Domain Administrator",
        "country": "US",
        "status": [
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
            "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
            "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
            "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
        ],
        "name_servers": ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM", "NS3.GOOGLE.COM", "NS4.GOOGLE.COM"],
    })()


@pytest.fixture
def fresh_domain_whois():
    """Simulated WHOIS response for a freshly registered domain."""
    now = datetime.now(timezone.utc)
    return type("WhoisResult", (), {
        "domain_name": "phishing-test-site.xyz",
        "creation_date": now - timedelta(days=2),
        "expiration_date": now + timedelta(days=363),
        "updated_date": now - timedelta(days=1),
        "registrar": "Some Unknown Registrar Ltd.",
        "org": None,
        "name": None,
        "country": "RU",
        "status": ["clientHold https://icann.org/epp#clientHold"],
        "name_servers": ["ns1.freehost.example"],
    })()


@pytest.fixture
def privacy_domain_whois():
    """Simulated WHOIS response for a privacy-protected domain."""
    now = datetime.now(timezone.utc)
    return type("WhoisResult", (), {
        "domain_name": "hidden-domain.com",
        "creation_date": now - timedelta(days=200),
        "expiration_date": now + timedelta(days=530),
        "updated_date": now - timedelta(days=30),
        "registrar": "Namecheap, Inc.",
        "org": "WhoisGuard Protected",
        "name": "WhoisGuard, Inc.",
        "country": "PA",
        "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
        "name_servers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
    })()


@pytest.fixture
def none_dates_whois():
    """Simulated WHOIS response with missing date fields (common for ccTLDs)."""
    return type("WhoisResult", (), {
        "domain_name": "example.cn",
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrar": "Unknown Chinese Registrar",
        "org": None,
        "name": None,
        "country": "CN",
        "status": [],
        "name_servers": [],
    })()
