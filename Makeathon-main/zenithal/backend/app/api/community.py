"""
Zenithal — Community Intelligence API (mounted under /api/v1/community).

Crowdsourced URL reputation endpoints:
  POST /report         — submit a URL report
  GET  /reputation     — query URL reputation (community + AI-fused)
  POST /vote-safe      — upvote a URL as safe
  POST /vote-malicious — downvote a URL as malicious
"""

from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

from app import db
from app.engines.url_engine import engine as url_engine

community_router = APIRouter()


# --- Schemas ---------------------------------------------------------------

class ReportRequest(BaseModel):
    device_id: str
    url: str
    reason: str = ""


class VoteRequest(BaseModel):
    device_id: str
    url: str


class ReputationQuery(BaseModel):
    url: str


# --- Helpers ---------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract domain from a URL string."""
    try:
        if "://" not in url:
            url = "http://" + url
        return urlparse(url).netloc or ""
    except Exception:
        return ""


# --- Routes ----------------------------------------------------------------

@community_router.post("/report")
async def report_url(req: ReportRequest) -> dict:
    """
    Submit a phishing/suspicious URL report.
    Reports never immediately flip a URL's status — they contribute to the
    community risk score which is fused with AI engines.
    """
    domain = _extract_domain(req.url)
    user = await db.get_or_create_user(req.device_id)
    url_entry = await db.get_or_create_community_url(req.url, domain)
    report = await db.add_report(user.id, url_entry.id, req.reason)

    # Re-fetch the URL to get updated counts
    updated_url = await db.get_community_url(req.url)

    return {
        "status": "reported",
        "report_id": report.id,
        "url": req.url,
        "domain": domain,
        "report_count": updated_url.report_count if updated_url else 1,
        "community_risk_score": updated_url.risk_score if updated_url else 50.0,
        "url_status": updated_url.status if updated_url else "unverified",
        "user_trust_score": user.trust_score,
    }


@community_router.get("/reputation")
async def get_reputation(url: str) -> dict:
    """
    Query the combined reputation of a URL.
    Fuses community reports (trust-weighted) with existing AI engines
    (lexical ML + WHOIS + SSL + IP) via the engine's 5-signal formula.
    """
    domain = _extract_domain(url)

    # Community data (may be None if URL was never reported)
    community_entry = await db.get_community_url(url)

    community_data = None
    community_score_for_engine: float | None = None
    if community_entry:
        community_data = community_entry.to_dict()
        if community_data["report_count"] > 0:
            community_score_for_engine = community_data["risk_score"]

    # AI analysis with community signal blended in via _fuse_scores
    ai_result = url_engine.analyze(
        url, with_ip_intel=True,
        community_score=community_score_for_engine,
    )
    fused_score = round(ai_result.get("score", 50.0), 1)

    # Status uses strengthened threshold guards from db._compute_status
    report_count = community_data["report_count"] if community_data else 0
    safe_votes = community_data["safe_votes"] if community_data else 0
    malicious_votes = community_data["malicious_votes"] if community_data else 0
    community_risk = community_data["risk_score"] if community_data else 50.0

    if (
        community_risk >= 70
        and malicious_votes >= 3
        and report_count >= 3
        and fused_score >= 60
    ):
        status = "verified_phishing"
    elif community_risk < 30 and safe_votes >= 2:
        status = "safe"
    else:
        status = "unverified"

    return {
        "url": url,
        "domain": domain,
        "fused_risk_score": fused_score,
        "status": status,
        "ai_score": round(ai_result.get("score", 50.0), 1),
        "community_score": community_score_for_engine,
        "report_count": report_count,
        "safe_votes": safe_votes,
        "malicious_votes": malicious_votes,
        "verdict": ai_result.get("verdict", "SAFE"),
        "threat_type": ai_result.get("threat_type", ""),
        "reasons": ai_result.get("reasons", []),
        "whois_intelligence": ai_result.get("whois_intelligence"),
        "ssl_intelligence": ai_result.get("ssl_intelligence"),
    }


@community_router.post("/vote-safe")
async def vote_safe(req: VoteRequest) -> dict:
    """Record a 'safe' vote for a URL from a community user."""
    domain = _extract_domain(req.url)
    _user = await db.get_or_create_user(req.device_id)  # ensure user exists
    updated = await db.vote_url(req.url, domain, "safe")
    return {
        "status": "voted_safe",
        "url": req.url,
        "safe_votes": updated.safe_votes,
        "malicious_votes": updated.malicious_votes,
        "community_risk_score": updated.risk_score,
        "url_status": updated.status,
    }


@community_router.post("/vote-malicious")
async def vote_malicious(req: VoteRequest) -> dict:
    """Record a 'malicious' vote for a URL from a community user."""
    domain = _extract_domain(req.url)
    _user = await db.get_or_create_user(req.device_id)  # ensure user exists
    updated = await db.vote_url(req.url, domain, "malicious")
    return {
        "status": "voted_malicious",
        "url": req.url,
        "safe_votes": updated.safe_votes,
        "malicious_votes": updated.malicious_votes,
        "community_risk_score": updated.risk_score,
        "url_status": updated.status,
    }
