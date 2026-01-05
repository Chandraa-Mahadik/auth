import logging
import random
import time
import uuid

from pythonjsonlogger import jsonlogger
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings


def setup_logging():
    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [handler]

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_client_ip(request: Request) -> str | None:
    """
    Proxy-safe client IP extraction.
    - If behind Nginx/LB, X-Forwarded-For is usually present.
    - First IP in XFF is the real client (when configured correctly).
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip() or None

    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip() or None

    return request.client.host if request.client else None


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get("X-Request-ID")

        # 4.1 store UUID object (not string)
        try:
            req_uuid = uuid.UUID(incoming) if incoming else uuid.uuid4()
        except Exception:
            req_uuid = uuid.uuid4()

        start = time.time()
        sampled = random.random() <= float(settings.LOG_SAMPLE_RATE)
        
        ip = get_client_ip(request)

        # Save consistent request context on request.state
        request.state.request_id = req_uuid
        # request.state.client_ip = get_client_ip(request)
        request.state.ip = ip                  # ✅ canonical, required
        request.state.client_ip = ip           # ✅ backward compatibility
        request.state.user_agent = request.headers.get("user-agent")

        response = await call_next(request)

        duration_ms = int((time.time() - start) * 1000)

        if sampled:
            logging.getLogger("app").info(
                "request",
                extra={
                    "request_id": str(req_uuid),
                    "path": request.url.path,
                    "method": request.method,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client": request.state.client_ip,
                },
            )

        response.headers["X-Request-ID"] = str(req_uuid)
        return response
