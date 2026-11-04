import os
from typing import Literal

from pydantic import BaseModel

DEFAULT_HMAC_SECRET = "change-me-in-prod-hmac-key"


class Settings(BaseModel):
    UPSTREAM_OPENAI_URL: str = "https://api.openai.com/v1"
    UPSTREAM_GEMINI_URL: str = "https://generativelanguage.googleapis.com"
    # agy's default Code Assist backend when signed in with a Google account (CLOUD_CODE_URL).
    UPSTREAM_CODE_ASSIST_URL: str = "https://daily-cloudcode-pa.googleapis.com"
    UPSTREAM_API_KEY: str = ""
    VAULT_HMAC_SECRET: str = DEFAULT_HMAC_SECRET
    DB_PATH: str = "/data/vault.db"
    VAULT_FALLBACK_SESSION: str = ""
    CUSTOM_REDACT_TERMS: str = ""
    MOCK_UPSTREAM: bool = False
    UPSTREAM_TIMEOUT_SECONDS: float = 600.0
    NER_BACKEND: Literal["none", "gliner"] = "none"
    NER_MODEL: str = "urchade/gliner_multi_pii-v1"
    NER_LABELS: str = "person:PERSON,school:SCHOOL,university:SCHOOL"
    NER_THRESHOLD: float = 0.5
    NER_IGNORE: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables; unset or empty values keep their defaults."""
        values = {name: os.environ[name] for name in cls.model_fields if os.environ.get(name)}
        if "UPSTREAM_OPENAI_URL" not in values and os.environ.get("UPSTREAM_BASE_URL"):
            values["UPSTREAM_OPENAI_URL"] = os.environ["UPSTREAM_BASE_URL"]  # pre-0.2 name
        return cls.model_validate(values)
