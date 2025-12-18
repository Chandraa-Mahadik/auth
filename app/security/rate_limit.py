from __future__ import annotations
import time
from redis.asyncio import Redis

_LUA_TOKEN_BUCKET = r"""
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl_sec = tonumber(ARGV[4])

local data = redis.call("HMGET", key, "tokens", "ts")
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  ts = now
else
  local delta = math.max(0, now - ts)
  tokens = math.min(capacity, tokens + delta * refill_per_sec)
  ts = now
end

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

redis.call("HMSET", key, "tokens", tokens, "ts", ts)
redis.call("EXPIRE", key, ttl_sec)

return allowed
"""


async def token_bucket_allow(
    redis: Redis,
    key: str,
    *,
    capacity: int,
    refill_per_sec: float,
    ttl_sec: int = 1800,
) -> bool:
    now = int(time.time())

    allowed = await redis.eval(
        _LUA_TOKEN_BUCKET,
        1,               # number of KEYS
        key,             # KEYS[1]
        capacity,        # ARGV[1]
        refill_per_sec,  # ARGV[2]
        now,             # ARGV[3]
        ttl_sec,         # ARGV[4]
    )

    return bool(int(allowed))
