from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    app_name: str = "CyberSentinel AI"
    environment: str = "development"
    api_prefix: str = ""
    mongodb_uri: str = Field(
        default="mongodb://localhost:27017",
        validation_alias=AliasChoices("MONGODB_URI", "DATABASE_URL"),
    )
    mongodb_db_name: str = "cybersentinel"
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    ai_provider: str = "groq"
    ai_api_key: str = ""
    ai_api_url: str = "https://api.groq.com/openai/v1/chat/completions"
    ai_model: str = "llama-3.1-8b-instant"
    create_indexes_on_startup: bool = True

    model_config = SettingsConfigDict(env_file=ENV_FILE, env_file_encoding="utf-8", extra="ignore")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
