from typing import Protocol

class Mailer(Protocol):
    async def send_password_reset(self, *, to_email: str, reset_url: str) -> None:
        ...

# For now, implement a dev mailer that logs
class DevMailer:
    async def send_password_reset(self, *, to_email: str, reset_url: str) -> None:
        print(f"[DEV MAIL] to={to_email} reset_url={reset_url}")
