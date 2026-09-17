"""
Zenithal — optional caching layer.

Uses Redis when REDIS_URL is set (shared across workers, survives restarts);
otherwise a bounded in-process TTL cache so a single instance still avoids
recomputing identical scans. Both are best-effort: a cache failure never breaks
a request.
"""

import json
import time

from app import config

_redis = None
if config.REDIS_URL:
    try:
        import redis.asyncio as aioredis  # type: ignore
        _redis = aioredis.from_url(config.REDIS_URL, decode_responses=True)
    except Exception:
        _redis = None

# In-process fallback: {key: (expires_at, value)}
_local: dict[str, tuple[float, str]] = {}
_LOCAL_MAX = 5000


async def get(key: str):
    if _redis is not None:
        try:
            raw = await _redis.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            pass
    hit = _local.get(key)
    if hit and hit[0] > time.time():
        return json.loads(hit[1])
    if hit:
        _local.pop(key, None)
    return None


async def set(key: str, value, ttl: int | None = None):
    ttl = ttl or config.CACHE_TTL
    payload = json.dumps(value, default=str)
    if _redis is not None:
        try:
            await _redis.set(key, payload, ex=ttl)
            return
        except Exception:
            pass
    if len(_local) >= _LOCAL_MAX:
        _local.clear()  # simple bound; cache is best-effort
    _local[key] = (time.time() + ttl, payload)


def backend() -> str:
    return "redis" if _redis is not None else "in-process"
