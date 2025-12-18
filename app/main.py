from fastapi import FastAPI, Depends
from app.core.logging import setup_logging, RequestIDMiddleware
from app.routers import auth_router
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db import get_session
from fastapi.openapi.utils import get_openapi
from app.core.config import settings


setup_logging()
app = FastAPI(title="Auth Service", version="1.0.0")
app.add_middleware(RequestIDMiddleware)
app.include_router(auth_router)

#  mount dev router only if explicitly enabled
if settings.ENABLE_DEBUG_ENDPOINTS:
    from app.routers import dev_router
    app.include_router(dev_router)

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
