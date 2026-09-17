"""
Zenithal WAF middleware — real-time, automatic URL-attack blocking for developers.

Drop this in front of any FastAPI / Starlette app. It inspects every incoming
request's URL (path + query) for SQLi / XSS / traversal / command-injection /
LFI using Zenithal's high-precision signature engine, and:
  * BLOCKS the request with 403 if an attack payload is detected, and
  * reports it to the Zenithal dashboard (fire-and-forget) so the attacker IP
    shows up on the live SOC map.

This is the "protect my server automatically" story — no log upload, decisions
happen inline in microseconds (pure regex, no model needed).

Usage:
    from integrations.waf_middleware import ZenithalWAF
    app.add_middleware(ZenithalWAF, report_url="http://127.0.0.1:8000")
"""

import sys
import os
import asyncio
from urllib.parse import unquote_plus

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Reuse Zenithal's signature engine (no network, no model load needed).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.ml.features_payload import signature_scan  # noqa: E402

try:
    import httpx
    _HAS_HTTPX = True
except Exception:
    _HAS_HTTPX = False


class ZenithalWAF(BaseHTTPMiddleware):
    def __init__(self, app, report_url: str | None = None, block: bool = True):
        super().__init__(app)
        self.report_url = report_url.rstrip("/") if report_url else None
        self.block = block

    async def dispatch(self, request: Request, call_next):
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query

        hits = signature_scan(unquote_plus(target))
        if hits:
            client_ip = request.client.host if request.client else "0.0.0.0"
            primary = hits[0]
            if self.report_url:
                asyncio.create_task(self._report(client_ip, request.method, target, hits))
            if self.block:
                return JSONResponse(
                    status_code=403,
                    content={
                        "blocked_by": "Zenithal WAF",
                        "attack_type": primary["attack_type"],
                        "reason": primary["label"],
                        "detail": "Request blocked: URL-based attack payload detected.",
                    },
                )
        return await call_next(request)

    async def _report(self, ip, method, target, hits):
        """Push a synthetic access-log line to Zenithal so the attack + IP land
        on the dashboard. Best-effort; never affects the protected app."""
        if not _HAS_HTTPX:
            return
        line = f'{ip} - - [-] "{method} {target} HTTP/1.1" 403 0 "-" "-"'
        try:
            async with httpx.AsyncClient() as c:
                await c.post(f"{self.report_url}/api/v1/analyze/logtext",
                             json={"text": line}, timeout=3)
        except Exception:
            pass
