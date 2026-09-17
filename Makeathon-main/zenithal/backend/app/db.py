"""
Zenithal — persistence (async SQLite via SQLAlchemy 2.0).

Two tables:
  detections   — every scored event (URL scans + log-derived attacks)
  attacker_ips — rolling per-IP profile aggregated from log analysis

SQLite keeps the demo zero-infra: no Postgres/Redis to stand up.
"""

import json
from datetime import datetime, timezone

from sqlalchemy import String, Float, Integer, DateTime, Text, select, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app import config

engine = create_async_engine(config.DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    channel: Mapped[str] = mapped_column(String(32), index=True)          # url | log | message
    input: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(16), index=True)          # MALICIOUS | SUSPICIOUS | SAFE
    threat_type: Mapped[str] = mapped_column(String(64), default="")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    src_ip: Mapped[str] = mapped_column(String(45), default="", index=True)
    country: Mapped[str] = mapped_column(String(64), default="")
    lat: Mapped[float] = mapped_column(Float, default=0.0)
    lon: Mapped[float] = mapped_column(Float, default=0.0)
    reasons: Mapped[str] = mapped_column(Text, default="[]")              # JSON list
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "channel": self.channel,
            "input": self.input,
            "verdict": self.verdict,
            "threat_type": self.threat_type,
            "score": self.score,
            "src_ip": self.src_ip,
            "country": self.country,
            "lat": self.lat,
            "lon": self.lon,
            "reasons": json.loads(self.reasons or "[]"),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AttackerIP(Base):
    __tablename__ = "attacker_ips"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    country: Mapped[str] = mapped_column(String(64), default="")
    org: Mapped[str] = mapped_column(String(128), default="")
    lat: Mapped[float] = mapped_column(Float, default=0.0)
    lon: Mapped[float] = mapped_column(Float, default=0.0)
    total_hits: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    attack_types: Mapped[str] = mapped_column(Text, default="{}")         # JSON
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "org": self.org,
            "lat": self.lat,
            "lon": self.lon,
            "total_hits": self.total_hits,
            "risk_score": self.risk_score,
            "attack_types": json.loads(self.attack_types or "{}"),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


# =========================================================================
# Community Intelligence Layer — crowdsourced URL reputation
# =========================================================================

class CommunityURL(Base):
    """A URL tracked by the community reporting system."""
    __tablename__ = "community_urls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=50.0)
    report_count: Mapped[int] = mapped_column(Integer, default=0)
    safe_votes: Mapped[int] = mapped_column(Integer, default=0)
    malicious_votes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="unverified")  # unverified | safe | verified_phishing
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "report_count": self.report_count,
            "safe_votes": self.safe_votes,
            "malicious_votes": self.malicious_votes,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class CommunityUser(Base):
    """Anonymous user identified by device_id (UUID). No login system."""
    __tablename__ = "community_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    trust_score: Mapped[float] = mapped_column(Float, default=50.0)
    correct_reports: Mapped[int] = mapped_column(Integer, default=0)
    false_reports: Mapped[int] = mapped_column(Integer, default=0)
    total_reports: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "trust_score": self.trust_score,
            "correct_reports": self.correct_reports,
            "false_reports": self.false_reports,
            "total_reports": self.total_reports,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class CommunityReport(Base):
    """Individual report from a community user about a URL."""
    __tablename__ = "community_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)   # FK to CommunityUser.id
    url_id: Mapped[int] = mapped_column(Integer, index=True)    # FK to CommunityURL.id
    reason: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending | confirmed | rejected

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url_id": self.url_id,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "status": self.status,
        }


# --- Community CRUD helpers -----------------------------------------------

async def get_or_create_user(device_id: str) -> CommunityUser:
    """Find an existing user by device_id, or create a new one (trust_score=50)."""
    async with SessionLocal() as session:
        result = await session.execute(
            select(CommunityUser).where(CommunityUser.device_id == device_id)
        )
        user = result.scalars().first()
        if user is None:
            user = CommunityUser(device_id=device_id)
            session.add(user)
            await session.commit()
            await session.refresh(user)
        return user


async def get_or_create_community_url(url: str, domain: str = "") -> CommunityURL:
    """Find an existing community URL record, or create a new one."""
    async with SessionLocal() as session:
        result = await session.execute(
            select(CommunityURL).where(CommunityURL.url == url)
        )
        entry = result.scalars().first()
        if entry is None:
            entry = CommunityURL(url=url, domain=domain)
            session.add(entry)
            await session.commit()
            await session.refresh(entry)
        return entry


async def get_community_url(url: str) -> CommunityURL | None:
    """Lookup a URL in the community database. Returns None if not found."""
    async with SessionLocal() as session:
        result = await session.execute(
            select(CommunityURL).where(CommunityURL.url == url)
        )
        return result.scalars().first()


async def add_report(user_id: int, url_id: int, reason: str) -> CommunityReport:
    """Create a new report and increment the URL's report_count."""
    async with SessionLocal() as session:
        report = CommunityReport(user_id=user_id, url_id=url_id, reason=reason)
        session.add(report)

        # Increment report count on the URL
        result = await session.execute(
            select(CommunityURL).where(CommunityURL.id == url_id)
        )
        url_entry = result.scalars().first()
        if url_entry:
            url_entry.report_count += 1
            url_entry.malicious_votes += 1  # a report implies malicious vote
            url_entry.updated_at = datetime.now(timezone.utc)

        # Increment user's total_reports
        user_result = await session.execute(
            select(CommunityUser).where(CommunityUser.id == user_id)
        )
        user = user_result.scalars().first()
        if user:
            user.total_reports += 1

        await session.commit()
        await session.refresh(report)
        return report


async def vote_url(url: str, domain: str, vote: str) -> CommunityURL:
    """Record a safe or malicious vote for a URL."""
    entry = await get_or_create_community_url(url, domain)
    async with SessionLocal() as session:
        result = await session.execute(
            select(CommunityURL).where(CommunityURL.id == entry.id)
        )
        url_entry = result.scalars().first()
        if url_entry:
            if vote == "safe":
                url_entry.safe_votes += 1
            elif vote == "malicious":
                url_entry.malicious_votes += 1
            url_entry.updated_at = datetime.now(timezone.utc)
            # Recalculate community risk score from trust-weighted votes
            url_entry.risk_score = _compute_community_score(url_entry)
            # Update status with threshold guards (never flip instantly)
            url_entry.status = _compute_status(
                url_entry.risk_score, url_entry.report_count,
                url_entry.safe_votes, url_entry.malicious_votes,
            )
            await session.commit()
            await session.refresh(url_entry)
            return url_entry
    return entry


async def adjust_trust_score(
    user_id: int, delta: float, correct: bool = True
) -> CommunityUser | None:
    """
    Adjust a community user's trust score and correct/false report counters.

    - `delta`  : points to add (positive) or subtract (negative)
    - `correct`: if True  → increments correct_reports
                 if False → increments false_reports
    Trust score is clamped to [0, 100].
    """
    async with SessionLocal() as session:
        result = await session.execute(
            select(CommunityUser).where(CommunityUser.id == user_id)
        )
        user = result.scalars().first()
        if user is None:
            return None
        user.trust_score = max(0.0, min(100.0, user.trust_score + delta))
        if correct:
            user.correct_reports += 1
        else:
            user.false_reports += 1
        await session.commit()
        await session.refresh(user)
        return user


async def update_community_url_score(
    url: str, engine_score: float | None = None
) -> CommunityURL | None:
    """
    Recompute risk_score and status for a community URL, optionally blending
    with the AI engine score for verified_phishing determination.
    """
    async with SessionLocal() as session:
        result = await session.execute(
            select(CommunityURL).where(CommunityURL.url == url)
        )
        url_entry = result.scalars().first()
        if url_entry is None:
            return None
        url_entry.risk_score = _compute_community_score(url_entry)
        url_entry.status = _compute_status(
            url_entry.risk_score, url_entry.report_count,
            url_entry.safe_votes, url_entry.malicious_votes,
            engine_score=engine_score,
        )
        url_entry.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(url_entry)
        return url_entry


def _compute_community_score(url_entry: CommunityURL) -> float:
    """Compute community-driven risk score from votes (0–100)."""
    total_votes = url_entry.safe_votes + url_entry.malicious_votes
    if total_votes == 0:
        return 50.0  # neutral
    malicious_ratio = url_entry.malicious_votes / total_votes
    # Scale to 0–100, with a base of 50 for equal votes
    return round(min(100.0, max(0.0, malicious_ratio * 100)), 1)


def _compute_status(
    risk_score: float,
    report_count: int = 0,
    safe_votes: int = 0,
    malicious_votes: int = 0,
    engine_score: float | None = None,
) -> str:
    """
    Determine URL status from combined signals.

    Threshold guards — a report or vote never immediately flips status:
      • verified_phishing: community risk ≥ 70 AND ≥ 3 malicious reports
                           AND (engine agrees ≥ 60 when available)
      • safe:              community risk < 30 AND ≥ 2 safe votes
      • Otherwise:         unverified
    """
    if (
        risk_score >= 70
        and malicious_votes >= 3
        and report_count >= 3
        and (engine_score is None or engine_score >= 60)
    ):
        return "verified_phishing"
    if risk_score < 30 and safe_votes >= 2:
        return "safe"
    return "unverified"


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def save_detection(data: dict) -> dict:
    """Persist a scored event. `data` uses engine output keys."""
    intel = data.get("ip_intel") or {}
    async with SessionLocal() as session:
        det = Detection(
            channel=data.get("channel", "url"),
            input=data.get("input", "")[:2000],
            verdict=data.get("verdict", "SAFE"),
            threat_type=data.get("threat_type", ""),
            score=float(data.get("score", 0.0)),
            src_ip=data.get("src_ip") or data.get("resolved_ip") or intel.get("ip", "") or "",
            country=intel.get("country", ""),
            lat=float(intel.get("lat", 0.0) or 0.0),
            lon=float(intel.get("lon", 0.0) or 0.0),
            reasons=json.dumps(data.get("reasons", [])),
        )
        session.add(det)
        await session.commit()
        await session.refresh(det)
        return det.to_dict()


async def upsert_attacker(profile: dict) -> None:
    intel = profile.get("intel", {}) or {}
    async with SessionLocal() as session:
        existing = await session.get(AttackerIP, profile["ip"])
        if existing is None:
            existing = AttackerIP(ip=profile["ip"])
            session.add(existing)
        existing.country = intel.get("country", "")
        existing.org = intel.get("org", "")
        existing.lat = float(intel.get("lat", 0.0) or 0.0)
        existing.lon = float(intel.get("lon", 0.0) or 0.0)
        existing.total_hits = int(profile.get("total_hits", 0))
        existing.risk_score = float(profile.get("risk_score", 0.0))
        existing.attack_types = json.dumps(profile.get("attack_types", {}))
        existing.last_seen = datetime.now(timezone.utc)
        await session.commit()


async def recent_detections(limit: int = 100) -> list[dict]:
    async with SessionLocal() as session:
        rows = (await session.execute(
            select(Detection).order_by(Detection.created_at.desc()).limit(limit)
        )).scalars().all()
        return [r.to_dict() for r in rows]


async def top_attackers(limit: int = 25) -> list[dict]:
    async with SessionLocal() as session:
        rows = (await session.execute(
            select(AttackerIP).order_by(AttackerIP.risk_score.desc()).limit(limit)
        )).scalars().all()
        return [r.to_dict() for r in rows]


async def stats() -> dict:
    async with SessionLocal() as session:
        total = (await session.execute(select(func.count(Detection.id)))).scalar() or 0
        malicious = (await session.execute(
            select(func.count(Detection.id)).where(Detection.verdict == "MALICIOUS")
        )).scalar() or 0
        suspicious = (await session.execute(
            select(func.count(Detection.id)).where(Detection.verdict == "SUSPICIOUS")
        )).scalar() or 0
        attackers = (await session.execute(select(func.count(AttackerIP.ip)))).scalar() or 0
        countries = (await session.execute(
            select(func.count(func.distinct(Detection.country))).where(Detection.country != "")
        )).scalar() or 0

        # verdict/channel breakdowns
        by_channel_rows = (await session.execute(
            select(Detection.channel, func.count(Detection.id)).group_by(Detection.channel)
        )).all()
        return {
            "total_detections": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "safe": total - malicious - suspicious,
            "unique_attackers": attackers,
            "countries": countries,
            "by_channel": {c: n for c, n in by_channel_rows},
        }
