from fastapi import FastAPI, Depends
from app.core.logging import setup_logging, RequestIDMiddleware
from app.routers import auth
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db import get_session
from fastapi.openapi.utils import get_openapi
from app.core.config import settings
import time
from datetime import datetime

setup_logging()
app = FastAPI(title="Auth Service", version="1.0.0")
app.add_middleware(RequestIDMiddleware)
app.include_router(auth.router)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    )
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.get("/healthz/db")
async def health_db(session: AsyncSession = Depends(get_session)):
    await session.execute(text("SELECT 1"))
    return {"db": "ok"}

# --- DEV DEBUG ONLY: verify time & config actually used by the server ---
@app.get("/debug/time")
def debug_time():
    return {
        "utc_iso": datetime.utcnow().isoformat() + "Z",
        "local_iso": datetime.now().isoformat(),
        "epoch": int(time.time()),
    }

@app.get("/debug/config")
def debug_config():
    return {
        "ACCESS_TOKEN_EXPIRES_MIN": settings.ACCESS_TOKEN_EXPIRES_MIN,
        "REFRESH_TOKEN_EXPIRES_DAYS": settings.REFRESH_TOKEN_EXPIRES_DAYS,
        "JWT_ALGORITHM": settings.JWT_ALGORITHM,
    }
