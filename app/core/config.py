from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRES_MIN: int = 15
    REFRESH_TOKEN_EXPIRES_DAYS: int = 30
    APP_COOKIE_DOMAIN: str | None = None
    LOG_SAMPLE_RATE: float = 1.0  # 0..1

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

settings = Settings()
