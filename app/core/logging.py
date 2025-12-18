import logging, os, random, time, uuid
from pythonjsonlogger import jsonlogger
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings

def setup_logging():
    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [handler]
    # quiet noisy libs if needed
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        start = time.time()
        # sampling (reduce log volume)
        sampled = random.random() <= float(settings.LOG_SAMPLE_RATE)
        request.state.request_id = req_id
        response = await call_next(request)
        duration_ms = int((time.time() - start) * 1000)
        if sampled:
            logging.getLogger("app").info(
                "request",
                extra={
                    "request_id": req_id,
                    "path": request.url.path,
                    "method": request.method,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client": request.client.host if request.client else None,
                },
            )
        response.headers["X-Request-ID"] = req_id
        return response
