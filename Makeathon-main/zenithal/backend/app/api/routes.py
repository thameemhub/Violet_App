"""
Zenithal — API routes (mounted under /api/v1).

Production features (all demo-safe / opt-in):
  * API-key auth + rate limiting via the `guard` dependency (app/security.py)
  * Result caching for repeated URL scans (app/cache.py)
  * Automatic alerts on high-risk detections (app/alerts.py)
  * Batch endpoint for high-throughput scanning
"""

import re

from fastapi import APIRouter, Depends, UploadFile, File, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app import db, cache, alerts, config
from app.engines import ip_intel, reputation
from app.engines.url_engine import engine as url_engine
from app.engines.payload_engine import engine as payload_engine
from app.security import guard
from app.ws import hub

router = APIRouter()

_URL_RE = re.compile(r"(https?://[^\s<>\"']+|(?:www\.|bit\.ly/|tinyurl\.com/)[^\s<>\"']+)", re.I)


# --- Schemas -------------------------------------------------------------
class URLRequest(BaseModel):
    url: str


class URLBatchRequest(BaseModel):
    urls: list[str]


class MessageRequest(BaseModel):
    text: str
    sender: str | None = None


class LogTextRequest(BaseModel):
    text: str


# --- Shared scan helper (cache -> analyze -> persist -> stream -> alert) --
async def _scan_url(url: str, channel: str = "url") -> dict:
    cache_key = f"url:{channel}:{url}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    result = url_engine.analyze(url)
    result["channel"] = channel
    saved = await db.save_detection(result)
    await hub.broadcast("detection", saved)
    result["id"] = saved["id"]
    result["created_at"] = saved["created_at"]

    alerts.maybe_alert({**result, "src_ip": result.get("resolved_ip", ""),
                        "country": (result.get("ip_intel") or {}).get("country", "")})
    await cache.set(cache_key, result)
    return result


# --- Health --------------------------------------------------------------
@router.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "url_model": "loaded" if url_engine.loaded else "heuristic-fallback",
        "payload_model": "loaded" if payload_engine.loaded else "signature-only",
        "geo_backend": ip_intel.geo_backend(),
        "reputation": reputation.stats(),
        "cache": cache.backend(),
        "auth": "required" if config.REQUIRE_API_KEY else "open",
        "alerts": "on" if alerts.enabled() else "off",
        "ws_clients": hub.count,
    }


# --- Engine 1: URL -------------------------------------------------------
@router.post("/analyze/url")
async def analyze_url(req: URLRequest, _=Depends(guard)) -> dict:
    return await _scan_url(req.url)


@router.post("/analyze/urls")
async def analyze_urls(req: URLBatchRequest, _=Depends(guard)) -> dict:
    """Batch scan — the entry point for high-throughput / bulk use."""
    results = [await _scan_url(u) for u in req.urls[:1000]]
    return {"count": len(results), "results": results}


# --- WhatsApp / SMS message (extract + scan URLs) ------------------------
@router.post("/analyze/message")
async def analyze_message(req: MessageRequest, _=Depends(guard)) -> dict:
    urls = _URL_RE.findall(req.text)
    urls = [u if "://" in u else "http://" + u for u in urls]
    order = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
    results, worst = [], "SAFE"
    for u in urls:
        r = await _scan_url(u, channel="message")
        results.append(r)
        if order[r["verdict"]] > order[worst]:
            worst = r["verdict"]
    return {
        "sender": req.sender,
        "urls_found": len(urls),
        "overall_verdict": worst if urls else "SAFE",
        "results": results,
    }


# --- Engine 2: logs ------------------------------------------------------
@router.post("/analyze/logfile")
async def analyze_logfile(file: UploadFile = File(...), _=Depends(guard)) -> dict:
    raw = (await file.read()).decode("utf-8", errors="ignore")
    return await _process_log(raw)


@router.post("/analyze/logtext")
async def analyze_logtext(req: LogTextRequest, _=Depends(guard)) -> dict:
    return await _process_log(req.text)


async def _process_log(raw: str) -> dict:
    report = payload_engine.analyze_log(raw)
    for profile in report["attackers"]:
        await db.upsert_attacker(profile)
        intel = profile.get("intel", {}) or {}
        top_type = max(profile["attack_types"], key=profile["attack_types"].get) if profile["attack_types"] else "URL Attack"
        event = {
            "channel": "log",
            "input": f"{profile['total_hits']} attacks from {profile['ip']}",
            "verdict": "MALICIOUS" if profile["risk_score"] >= 70 else "SUSPICIOUS",
            "threat_type": top_type,
            "score": profile["risk_score"],
            "src_ip": profile["ip"],
            "country": intel.get("country", ""),
            "ip_intel": intel,
            "reasons": profile["reasons"],
        }
        saved = await db.save_detection(event)
        await hub.broadcast("detection", saved)
        alerts.maybe_alert(event)
    return report


# --- IP lookup (standalone) ---------------------------------------------
@router.get("/ip/{ip}")
async def ip_lookup(ip: str, _=Depends(guard)) -> dict:
    return ip_intel.lookup_ip(ip)


# --- Dashboard (read-only; no key required so the UI just works) ----------
@router.get("/dashboard/stats")
async def dashboard_stats() -> dict:
    return await db.stats()


@router.get("/dashboard/detections")
async def dashboard_detections(limit: int = 100) -> dict:
    return {"detections": await db.recent_detections(limit)}


@router.get("/dashboard/attackers")
async def dashboard_attackers(limit: int = 25) -> dict:
    return {"attackers": await db.top_attackers(limit)}


# --- WebSocket feed ------------------------------------------------------
@router.websocket("/ws/feed")
async def ws_feed(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(ws)
    except Exception:
        await hub.disconnect(ws)
