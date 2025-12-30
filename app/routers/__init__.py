from .auth import router as auth_router
from .dev import router as dev_router

# ✅ Add these once the files exist
# (create: app/routers/password_reset.py, app/routers/sessions.py)
from .password_reset import router as password_reset_router
from .sessions import router as sessions_router

__all__ = [
    "auth_router",
    "dev_router",
    "password_reset_router",
    "sessions_router",
]