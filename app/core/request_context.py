from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import uuid

from fastapi import Request

@dataclass(frozen=True)
class RequestContext:
    request_id: Optional[uuid.UUID]
    ip: Optional[str]
    user_agent: Optional[str]

def get_request_context(request: Request) -> RequestContext:
    # request_id should be placed on request.state by middleware
    rid = getattr(request.state, "request_id", None)

    # handle reverse proxy setups later (X-Forwarded-For), for now simple
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    return RequestContext(request_id=rid, ip=ip, user_agent=ua)
