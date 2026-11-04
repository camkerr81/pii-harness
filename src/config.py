import os

from pydantic import BaseModel

DEFAULT_HMAC_SECRET = "change-me-in-prod-hmac-key"


class Settings(BaseModel):
    UPSTREAM_BASE_URL: str = "https://api.openai.com/v1"
    UPSTREAM_API_KEY: str = ""
    VAULT_HMAC_SECRET: str = DEFAULT_HMAC_SECRET
    DB_PATH: str = "/data/vault.db"
    MOCK_UPSTREAM: bool = False
    UPSTREAM_TIMEOUT_SECONDS: float = 600.0

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables; unset or empty values keep their defaults."""
        values = {name: os.environ[name] for name in cls.model_fields if os.environ.get(name)}
        return cls.model_validate(values)
