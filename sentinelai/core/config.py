"""
Central configuration for SentinelAI.
All settings loaded from environment variables / .env file.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):

    # ── LLM providers ─────────────────────────────────────────────────────
    anthropic_api_key: str = Field(default="", env="ANTHROPIC_API_KEY")
    openai_api_key: str = Field(default="", env="OPENAI_API_KEY")

    # Default models
    anthropic_model: str = "claude-haiku-4-5"
    openai_model: str = "gpt-4o-mini"
    llm_timeout_seconds: int = 60
    llm_max_tokens: int = 4096

    # ── Threat intelligence APIs ───────────────────────────────────────────
    abuseipdb_api_key: str = Field(default="", env="ABUSEIPDB_API_KEY")
    nvd_api_key: str = Field(default="", env="NVD_API_KEY")

    # ── App config ─────────────────────────────────────────────────────────
    app_name: str = "SentinelAI"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", validation_alias="sentinelai_env")
    log_level: str = Field(default="INFO", validation_alias="sentinelai_log_level")
    max_scan_threads: int = Field(default=4, validation_alias="sentinelai_max_scan_threads")
    # ── Database ───────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinelai.db",
        env="DATABASE_URL"
    )

    # ── Scanning limits (safety) ───────────────────────────────────────────
    max_ports_per_scan: int = 1000
    scan_timeout_seconds: int = 300
    max_log_lines_per_analysis: int = 5000

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore"
    }

    def has_anthropic_key(self) -> bool:
        return bool(self.anthropic_api_key and self.anthropic_api_key != "sk-ant-...")

    def has_openai_key(self) -> bool:
        return bool(self.openai_api_key and self.openai_api_key != "sk-...")


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance — loaded once at startup."""
    return Settings()
