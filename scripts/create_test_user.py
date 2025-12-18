import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncio
from sqlalchemy import select

from app.db import get_session
from app.models import User
from app.core.security import hash_password  # <-- if your function name differs, see note below

EMAIL = "test@example.com"
PASSWORD = "Test@12345"
FULL_NAME = "Test User"


async def main():
    # get_session() is a dependency generator; we can consume it manually
    async for session in get_session():
        res = await session.execute(select(User).where(User.email == EMAIL))
        existing = res.scalar_one_or_none()

        if existing:
            print("User already exists:", EMAIL)
            return

        user = User(
            email=EMAIL,
            password_hash=hash_password(PASSWORD),
            full_name=FULL_NAME,
            is_active=True,
        )

        session.add(user)
        await session.commit()
        print("Created user:", EMAIL)
        return


if __name__ == "__main__":
    asyncio.run(main())
