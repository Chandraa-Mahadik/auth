from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]  # points to project root (auth/)
ENV_FILE = BASE_DIR / ".env"

class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRES_MIN: int = 15
    REFRESH_TOKEN_EXPIRES_DAYS: int = 30
    APP_COOKIE_DOMAIN: str | None = None
    LOG_SAMPLE_RATE: float = 1.0  # 0..1
    ENABLE_DEBUG_ENDPOINTS: bool = False
    REDIS_URL: str = "redis://localhost:6379/0"
    RATE_BUCKET_SIZE: int = 5
    RATE_REFILL_PER_SEC: float = 0.1
    
    # Password reset
    PASSWORD_RESET_TOKEN_MINUTES: int = 30
    PASSWORD_RESET_TOKEN_BYTES: int = 32  # token entropy
    PASSWORD_RESET_RATE_BUCKET_SIZE: int = 5
    PASSWORD_RESET_RATE_REFILL_PER_SEC: float = 0.02  # ~1 request / 50 sec
    PASSWORD_RESET_EMAIL_COOLDOWN_SEC: int = 60

    # model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()
