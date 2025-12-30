from fastapi import FastAPI, Depends
from fastapi.openapi.utils import get_openapi
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.logging import setup_logging, RequestIDMiddleware
from app.core.config import settings
from app.db import get_session

# ✅ Routers (keep these imports explicit so missing routers are obvious)
from app.routers import auth_router

# If you add these routers, ensure they exist in app/routers/__init__.py
# OR import them directly from their module files (recommended).
try:
    from app.routers.password_reset import router as password_reset_router
except Exception:
    password_reset_router = None

try:
    from app.routers.sessions import router as sessions_router
except Exception:
    sessions_router = None


setup_logging()

app = FastAPI(title="Auth Service", version="1.0.0")
app.add_middleware(RequestIDMiddleware)

# ✅ Always mounted
app.include_router(auth_router)

# ✅ Mount optional routers if present
if password_reset_router is not None:
    app.include_router(password_reset_router)

if sessions_router is not None:
    app.include_router(sessions_router)

# ✅ Mount dev router only if explicitly enabled
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

    # Optional: define global security if you want (usually not for auth endpoints)
    # openapi_schema["security"] = [{"BearerAuth": []}]

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
