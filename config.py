"""
app/config.py — Application configuration.

pydantic-settings automatically reads from environment variables.
All validation happens at startup — the app refuses to start with broken config.
env-check validates the .env file against schema.json in CI BEFORE this runs.
"""
from functools import lru_cache
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Every field here maps directly to an environment variable.
    Pydantic validates types automatically — if DATABASE_URL is missing,
    you get a clear error at startup, not a cryptic crash 10 minutes later.
    """

    model_config = SettingsConfigDict(
        env_file=".env",          # Load from .env file locally
        env_file_encoding="utf-8",
        case_sensitive=True,       # DATABASE_URL ≠ database_url
    )

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str

    # ── Auth ──────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # ── Encryption ────────────────────────────────────────────────────────────
    # Must be exactly 32 bytes for AES-256
    AES_ENCRYPTION_KEY: str

    # ── Application ───────────────────────────────────────────────────────────
    APP_ENV: str = "dev"
    PORT: int = 8080

    # ── Fraud Detection ───────────────────────────────────────────────────────
    FRAUD_SCORE_THRESHOLD: float = 2.5
    MAX_TRANSFER_AMOUNT: float = 500_000.0  # In rupees

    # ── Validators ────────────────────────────────────────────────────────────
    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def jwt_secret_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError(
                f"JWT_SECRET_KEY must be at least 32 characters, got {len(v)}. "
                "Generate with: openssl rand -hex 32"
            )
        return v

    @field_validator("AES_ENCRYPTION_KEY")
    @classmethod
    def aes_key_must_be_32_bytes(cls, v: str) -> str:
        if len(v) != 32:
            raise ValueError(
                f"AES_ENCRYPTION_KEY must be exactly 32 characters for AES-256, got {len(v)}. "
                "Generate with: openssl rand -hex 16"
            )
        return v

    @field_validator("APP_ENV")
    @classmethod
    def app_env_must_be_valid(cls, v: str) -> str:
        allowed = {"dev", "staging", "prod"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}, got '{v}'")
        return v

    @model_validator(mode="after")
    def validate_database_url(self) -> "Settings":
        """Ensure database URL uses async driver (asyncpg, not psycopg2)."""
        url = self.DATABASE_URL
        # Convert sync postgres:// to async postgresql+asyncpg://
        if url.startswith("postgres://"):
            self.DATABASE_URL = url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgresql://") and "asyncpg" not in url:
            self.DATABASE_URL = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return self

    @property
    def aes_key_bytes(self) -> bytes:
        """Return AES key as bytes — what the crypto library needs."""
        return self.AES_ENCRYPTION_KEY.encode()

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "prod"

    @property
    def max_transfer_paise(self) -> int:
        """Convert rupees config to paise for internal use."""
        return int(self.MAX_TRANSFER_AMOUNT * 100)


@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    lru_cache means this is only created once per process.
    Use as a FastAPI dependency: settings = Depends(get_settings)
    """
    return Settings()
