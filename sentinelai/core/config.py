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
    llm_timeout_seconds: int = 300
    llm_max_tokens: int = 8000

    # ── LLM API Gateway (optional — routes all LLM calls through a proxy) ──
    # API key is generated from the gateway admin panel (Org → Keys → Generate).
    # Set LLM_GATEWAY_ENABLED=true and paste the key — no other config needed.
    llm_gateway_url: str = Field(default="", env="LLM_GATEWAY_URL")
    llm_gateway_api_key: str = Field(default="", env="LLM_GATEWAY_API_KEY")
    llm_gateway_enabled: bool = Field(default=False, env="LLM_GATEWAY_ENABLED")

    # ── Threat intelligence APIs ───────────────────────────────────────────
    abuseipdb_api_key: str = Field(default="", env="ABUSEIPDB_API_KEY")
    nvd_api_key: str = Field(default="", env="NVD_API_KEY")

    # ── App config ─────────────────────────────────────────────────────────
    app_name: str = "SentinelAI"
    app_version: str = "2.0.0"
    environment: str = Field(default="development", env="SENTINELAI_ENV")
    log_level: str = Field(default="INFO")
    max_scan_threads: int = Field(default=4)

    # ── API Keys & Rate limiting ───────────────────────────────────────────
    sentinelai_api_keys: str = Field(
        default="sentinel-dev-key-change-in-production",
        env="SENTINELAI_API_KEYS"
    )
    rate_limit_per_minute: int = Field(default=120)

    @property
    def api_keys(self) -> list:
        return [k.strip() for k in self.sentinelai_api_keys.split(',') if k.strip()]

    # ── Database ───────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinelai.db",
        env="DATABASE_URL"
    )

    # ── JWT Auth ───────────────────────────────────────────────────────────
    jwt_secret_key: str = Field(
        default="change-me-in-production-use-a-long-random-string",
        env="JWT_SECRET_KEY"
    )
    jwt_expire_hours: int = Field(default=24, env="JWT_EXPIRE_HOURS")

    # ── Admin bootstrap ────────────────────────────────────────────────────
    # Comma-separated emails that always receive/keep admin on registration or startup.
    admin_emails: str = Field(default="", env="ADMIN_EMAILS")

    # ── Notifications ─────────────────────────────────────────────────────
    slack_webhook_url: str = Field(default="", env="SLACK_WEBHOOK_URL")
    alert_min_severity: str = Field(default="critical", env="ALERT_MIN_SEVERITY")  # critical | high | any
    alert_email_to: str = Field(default="", env="ALERT_EMAIL_TO")
    smtp_host: str = Field(default="", env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: str = Field(default="", env="SMTP_USER")
    smtp_password: str = Field(default="", env="SMTP_PASSWORD")
    smtp_from: str = Field(default="", env="SMTP_FROM")

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