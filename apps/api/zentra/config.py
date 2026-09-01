"""Central application configuration.

All configuration comes from the environment. Nothing here contains a
credential default: production values must be supplied by the deployment
environment, and the settings validator refuses to start a production process
with development placeholders.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]


def _parse_rate(value: str) -> tuple[int, int]:
    """Parse a ``"<limit>/<window-seconds>"`` rate-limit string."""
    try:
        limit, window = value.split("/", 1)
        return int(limit), int(window)
    except (ValueError, AttributeError) as exc:  # pragma: no cover - config error path
        raise ValueError(f"Invalid rate limit {value!r}; expected '<count>/<seconds>'") from exc


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ----- runtime -----------------------------------------------------------
    environment: Environment = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    service_name: str = "zentra-api"

    # ----- urls --------------------------------------------------------------
    app_url: str = "http://localhost:3000"
    api_url: str = "http://localhost:8000"
    cors_allowed_origins: str = "http://localhost:3000"

    # ----- data stores -------------------------------------------------------
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/zentra"
    test_database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/zentra_test"
    db_pool_size: int = 5
    db_max_overflow: int = 10
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ----- auth --------------------------------------------------------------
    auth_provider: Literal["local", "supabase"] = "local"
    jwt_secret: str = ""
    jwt_issuer: str = "zentra"
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 1209600

    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""
    supabase_jwt_secret: str = ""

    # ----- scanning ----------------------------------------------------------
    use_mock_scanners: bool = True
    scanner_http_timeout_seconds: float = 15.0
    scanner_total_timeout_seconds: float = 180.0
    scanner_max_response_bytes: int = 2_000_000
    ssllabs_api_url: str = "https://api.ssllabs.com/api/v3"
    ssllabs_max_poll_seconds: int = 180
    hibp_api_key: str = ""
    hibp_api_url: str = "https://haveibeenpwned.com/api/v3"
    shodan_api_key: str = ""
    shodan_api_url: str = "https://api.shodan.io"
    nvd_api_key: str = ""
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json"
    # Allow scanning private address space. Only ever true inside the test suite.
    allow_private_scan_targets: bool = False

    # ----- billing -----------------------------------------------------------
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_starter_price_id: str = ""
    stripe_growth_price_id: str = ""
    stripe_scale_price_id: str = ""
    stripe_report_pack_price_id: str = ""

    # ----- email -------------------------------------------------------------
    email_provider: Literal["console", "resend"] = "console"
    resend_api_key: str = ""
    email_from: str = "Zentra <alerts@zentra.example>"

    # ----- slack -------------------------------------------------------------
    slack_client_id: str = ""
    slack_client_secret: str = ""
    slack_signing_secret: str = ""

    # ----- secret handling ---------------------------------------------------
    secrets_encryption_key: str = ""

    # ----- rate limiting -----------------------------------------------------
    rate_limit_enabled: bool = True
    public_scan_rate_limit: str = "3/3600"
    auth_rate_limit: str = "10/900"
    api_rate_limit: str = "300/60"
    manual_scan_rate_limit: str = "20/3600"
    report_rate_limit: str = "10/3600"

    # ----- feature flags -----------------------------------------------------
    feature_benchmarking: bool = True
    feature_slack: bool = False
    feature_teams: bool = True
    feature_mssp: bool = False
    feature_white_label: bool = True
    feature_public_api: bool = True
    feature_advanced_scanners: bool = True

    # ----- scheduling / alerting --------------------------------------------
    rescan_interval_hours: int = 24
    rescan_sweep_minutes: int = 30
    alert_score_delta_threshold: int = 10
    benchmark_min_sample_size: int = 5

    # ----- storage -----------------------------------------------------------
    report_storage_dir: str = "./storage/reports"
    max_logo_bytes: int = 524_288

    # ----- admin -------------------------------------------------------------
    zentra_admin_emails: str = ""

    sentry_dsn: str = ""

    # ------------------------------------------------------------------ helpers
    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if self.environment == "production":
            problems: list[str] = []
            if self.debug:
                problems.append("DEBUG must be false in production")
            if self.use_mock_scanners:
                problems.append("USE_MOCK_SCANNERS must be false in production")
            if self.allow_private_scan_targets:
                problems.append("ALLOW_PRIVATE_SCAN_TARGETS must be false in production")
            if not self.rate_limit_enabled:
                problems.append("RATE_LIMIT_ENABLED must be true in production")
            if len(self.jwt_secret) < 32:
                problems.append("JWT_SECRET must be set to at least 32 characters")
            if not self.secrets_encryption_key:
                problems.append("SECRETS_ENCRYPTION_KEY must be set in production")
            if self.auth_provider == "supabase" and not (
                self.supabase_url and self.supabase_service_role_key and self.supabase_jwt_secret
            ):
                problems.append("Supabase credentials are incomplete")
            if "*" in self.cors_allowed_origins:
                problems.append("CORS_ALLOWED_ORIGINS must not contain a wildcard in production")
            if problems:
                raise ValueError("Invalid production configuration: " + "; ".join(problems))
        if not self.jwt_secret:
            # Ephemeral per-process secret so local/test runs work without setup.
            # Production is blocked by the check above.
            object.__setattr__(self, "jwt_secret", secrets.token_hex(32))
        return self

    # ------------------------------------------------------------- derived
    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def admin_emails(self) -> set[str]:
        return {e.strip().lower() for e in self.zentra_admin_emails.split(",") if e.strip()}

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def effective_database_url(self) -> str:
        return self.test_database_url if self.environment == "test" else self.database_url

    def rate(self, name: str) -> tuple[int, int]:
        return _parse_rate(getattr(self, f"{name}_rate_limit"))

    def feature_enabled(self, name: str) -> bool:
        return bool(getattr(self, f"feature_{name}", False))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Used by tests that mutate the environment."""
    get_settings.cache_clear()
