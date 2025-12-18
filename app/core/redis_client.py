from __future__ import annotations

from redis.asyncio import Redis
from app.core.config import settings

_redis: Redis | None = None


def get_redis() -> Redis:
    """
    Singleton redis client. In FastAPI apps this is fine for now.
    Later (K8s), you can move to startup/shutdown handlers.
    """
    global _redis
    if _redis is None:
        _redis = Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,  # store/read strings cleanly
        )
    return _redis
