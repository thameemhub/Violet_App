"""
Zenithal — API-key auth + rate limiting.

Both are opt-in and demo-safe:
  * API-key auth only enforces when REQUIRE_API_KEY=true.
  * Rate limiting uses an in-process sliding window (no Redis needed) and is
    generous by default. It is per API-key when keys are on, else per client IP.
"""

import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, status

from app import config

# --- Rate limiter (in-process sliding window) ----------------------------
_hits: dict[str, deque] = defaultdict(deque)


def _rate_key(request: Request, api_key: str | None) -> str:
    if api_key:
        return f"key:{api_key}"
    client = request.client.host if request.client else "unknown"
    return f"ip:{client}"


def _check_rate(key: str) -> None:
    if config.RATE_LIMIT_MAX <= 0:
        return
    now = time.monotonic()
    window = config.RATE_LIMIT_WINDOW
    dq = _hits[key]
    while dq and dq[0] <= now - window:
        dq.popleft()
    if len(dq) >= config.RATE_LIMIT_MAX:
        retry = int(window - (now - dq[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({config.RATE_LIMIT_MAX}/{window}s). Retry in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    dq.append(now)


async def guard(request: Request, x_api_key: str | None = Header(default=None)) -> str | None:
    """FastAPI dependency: enforces API key (if enabled) then rate limit.
    Returns the authenticated key (or None when auth is disabled)."""
    if config.REQUIRE_API_KEY:
        if not x_api_key or x_api_key not in config.API_KEYS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid API key. Send header 'X-API-Key'.",
            )
    _check_rate(_rate_key(request, x_api_key))
    return x_api_key
