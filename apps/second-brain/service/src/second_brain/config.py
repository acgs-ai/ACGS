from functools import lru_cache
from ipaddress import ip_address, ip_network
from os import environ
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

LOCAL_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"
ALLOWED_ENVIRONMENT_KEYS = frozenset(
    {
        "SECOND_BRAIN_APP_ENV",
        "SECOND_BRAIN_AUTH_MODE",
        "SECOND_BRAIN_BIND_HOST",
        "SECOND_BRAIN_BIND_PORT",
        "SECOND_BRAIN_DATABASE_URL",
        "SECOND_BRAIN_EXCHANGE_RATE_LIMIT",
        "SECOND_BRAIN_EXCHANGE_RATE_WINDOW_SECONDS",
        "SECOND_BRAIN_PUBLIC_ORIGIN",
        "SECOND_BRAIN_POLICY_ENABLED",
        "SECOND_BRAIN_SESSION_ABSOLUTE_SECONDS",
        "SECOND_BRAIN_SESSION_IDLE_SECONDS",
        "SECOND_BRAIN_MODEL_PROVIDER",
        "SECOND_BRAIN_MODEL_BASE_URL",
        "SECOND_BRAIN_EMBEDDING_MODEL",
        "SECOND_BRAIN_EMBEDDING_DIMENSIONS",
        "SECOND_BRAIN_EMBEDDING_PROFILE_VERSION",
        "SECOND_BRAIN_ANSWER_MIN_SIMILARITY",
        "SECOND_BRAIN_STORAGE_BACKEND",
        "SECOND_BRAIN_STORAGE_ROOT",
        "SECOND_BRAIN_MAX_UPLOAD_BYTES",
        "SECOND_BRAIN_MAX_REQUEST_ENVELOPE_BYTES",
        "SECOND_BRAIN_REQUEST_BODY_TIMEOUT_SECONDS",
        "SECOND_BRAIN_MAX_EXTRACTED_CHARS",
        "SECOND_BRAIN_MAX_CHUNKS",
        "SECOND_BRAIN_MAX_PROCESSING_SECONDS",
        "SECOND_BRAIN_URL_MAX_REDIRECTS",
        "SECOND_BRAIN_URL_TIMEOUT_SECONDS",
        "SECOND_BRAIN_TRUSTED_ASSERTION_AUDIENCE",
        "SECOND_BRAIN_TRUSTED_ASSERTION_ISSUER",
        "SECOND_BRAIN_TRUSTED_PROXY_NETWORK",
        "SECOND_BRAIN_TRUSTED_PROXY_SECRET",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECOND_BRAIN_",
        env_file=LOCAL_ENV_FILE,
        extra="forbid",
    )

    app_env: Literal["development", "test", "production"] = "development"
    auth_mode: Literal["development_headers", "trusted_proxy"] = "development_headers"
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8000, ge=1, le=65535)
    database_url: SecretStr = Field(
        default=SecretStr(
            "postgresql+psycopg://second_brain_app:second_brain_app_dev@127.0.0.1:55439/second_brain"
        )
    )
    storage_backend: Literal["filesystem"] = "filesystem"
    storage_root: Path = Path(".second-brain-storage")
    max_upload_bytes: int = Field(default=10_000_000, ge=1, le=100_000_000)
    max_request_envelope_bytes: int = Field(default=12_000_000, ge=1, le=120_000_000)
    request_body_timeout_seconds: float = Field(default=10, gt=0, le=120)
    max_extracted_chars: int = Field(default=2_000_000, ge=1, le=20_000_000)
    max_chunks: int = Field(default=5000, ge=1, le=50_000)
    max_processing_seconds: int = Field(default=30, ge=1, le=300)
    url_max_redirects: int = Field(default=3, ge=0, le=10)
    url_timeout_seconds: float = Field(default=10, gt=0, le=60)
    model_provider: Literal["fake", "openai_compatible"] = "fake"
    model_base_url: str = "http://127.0.0.1:8001/v1"
    embedding_model: str = "text-embedding"
    embedding_dimensions: int = Field(default=8, ge=1, le=4096)
    embedding_profile_version: int = Field(default=1, ge=1, le=2_147_483_647)
    answer_min_similarity: float | None = Field(default=None, ge=-1.0, le=1.0)
    trusted_proxy_secret: SecretStr | None = None
    trusted_proxy_network: str | None = None
    trusted_assertion_issuer: str | None = None
    trusted_assertion_audience: str | None = None
    public_origin: str | None = None
    policy_enabled: bool = False
    session_idle_seconds: int = Field(default=1800, ge=60, le=86400)
    session_absolute_seconds: int = Field(default=86400, ge=300, le=604800)
    exchange_rate_limit: int = Field(default=20, ge=1, le=1000)
    exchange_rate_window_seconds: int = Field(default=60, ge=1, le=3600)

    def __init__(self, **values: Any) -> None:
        unknown = sorted(
            key
            for key in environ
            if key.startswith("SECOND_BRAIN_")
            and not key.startswith("SECOND_BRAIN_WORKER_")
            and not key.startswith("SECOND_BRAIN_ANSWER_")
            and key not in ALLOWED_ENVIRONMENT_KEYS
        )
        if unknown:
            raise ValueError(f"unknown Second Brain environment keys: {', '.join(unknown)}")
        super().__init__(**values)

    @model_validator(mode="after")
    def validate_trust_boundaries(self) -> "Settings":
        database_username = make_url(self.database_url.get_secret_value()).username
        if database_username != "second_brain_app":
            raise ValueError("runtime database URL must authenticate exactly as second_brain_app")
        try:
            bind_is_loopback = ip_address(self.bind_host).is_loopback
        except ValueError as exc:
            raise ValueError("bind_host must be an IP address") from exc
        if self.auth_mode == "development_headers" and not bind_is_loopback:
            raise ValueError("development_headers requires a loopback bind_host")
        if self.app_env == "production" and self.auth_mode == "development_headers":
            raise ValueError("development_headers auth_mode is forbidden in production")
        if self.app_env == "production" and (
            self.trusted_proxy_secret is None
            or not self.trusted_proxy_secret.get_secret_value().strip()
        ):
            raise ValueError("a trusted principal verifier is required in production")
        if self.app_env == "production":
            assert self.trusted_proxy_secret is not None
            if len(self.trusted_proxy_secret.get_secret_value().encode()) < 32:
                raise ValueError("trusted proxy HMAC secret must contain at least 32 bytes")
            required = {
                "trusted_proxy_network": self.trusted_proxy_network,
                "trusted_assertion_issuer": self.trusted_assertion_issuer,
                "trusted_assertion_audience": self.trusted_assertion_audience,
                "public_origin": self.public_origin,
            }
            missing = sorted(
                key for key, value in required.items() if not value or not value.strip()
            )
            if missing:
                raise ValueError(f"production identity settings are required: {', '.join(missing)}")
            assert self.trusted_proxy_network is not None
            trusted_network = ip_network(self.trusted_proxy_network, strict=False)
            endpoints = (trusted_network.network_address, trusted_network.broadcast_address)
            if (
                trusted_network.prefixlen == 0
                or trusted_network.num_addresses > 256
                or any(
                    endpoint.is_unspecified
                    or endpoint.is_global
                    or endpoint.is_multicast
                    or endpoint.is_reserved
                    for endpoint in endpoints
                )
            ):
                raise ValueError("trusted_proxy_network must be a bounded non-global network")
            assert self.public_origin is not None
            origin = urlsplit(self.public_origin)
            if origin.scheme != "https" or not origin.netloc or origin.path not in {"", "/"}:
                raise ValueError("public_origin must be an HTTPS origin without a path")
            if self.session_idle_seconds > self.session_absolute_seconds:
                raise ValueError("session idle expiry cannot exceed absolute expiry")
        return self


class WorkerSettings(BaseSettings):
    """Worker-only settings; deliberately never loaded by the API settings path."""

    model_config = SettingsConfigDict(
        env_prefix="SECOND_BRAIN_WORKER_",
        env_file=None,
        extra="forbid",
    )

    content_database_url: SecretStr = Field(
        default=SecretStr(
            "postgresql+psycopg://second_brain_app:second_brain_app_dev@127.0.0.1:55439/second_brain"
        )
    )
    dispatcher_database_url: SecretStr = Field(
        default=SecretStr(
            "postgresql+psycopg://second_brain_worker:second_brain_worker_dev@127.0.0.1:55439/second_brain"
        )
    )
    storage_backend: Literal["filesystem"] = "filesystem"
    storage_root: Path = Path(".second-brain-storage")
    max_upload_bytes: int = Field(default=10_000_000, ge=1, le=100_000_000)
    max_extracted_chars: int = Field(default=2_000_000, ge=1, le=20_000_000)
    max_chunks: int = Field(default=5000, ge=1, le=50_000)
    max_processing_seconds: int = Field(default=30, ge=1, le=300)
    stale_stage_age_seconds: int = Field(default=300, ge=1, le=86400)
    stale_stage_batch_size: int = Field(default=100, ge=1, le=1000)
    stale_stage_sweep_seconds: int = Field(default=30, ge=1, le=3600)
    url_max_redirects: int = Field(default=3, ge=0, le=10)
    url_timeout_seconds: float = Field(default=10, gt=0, le=60)
    model_provider: Literal["fake", "openai_compatible"] = "fake"
    model_api_key: SecretStr | None = None
    model_base_url: str = "http://127.0.0.1:8001/v1"
    embedding_model: str = "text-embedding"
    embedding_dimensions: int = Field(default=8, ge=1, le=4096)
    embedding_profile_version: int = Field(default=1, ge=1, le=2_147_483_647)
    answer_min_similarity: float | None = Field(default=None, ge=-1.0, le=1.0)

    @model_validator(mode="after")
    def validate_database_roles(self) -> "WorkerSettings":
        content_user = make_url(self.content_database_url.get_secret_value()).username
        dispatcher_user = make_url(self.dispatcher_database_url.get_secret_value()).username
        if content_user != "second_brain_app":
            raise ValueError("worker content database URL must authenticate as second_brain_app")
        if dispatcher_user != "second_brain_worker":
            raise ValueError(
                "worker dispatcher database URL must authenticate as second_brain_worker"
            )
        return self


class AnswerProviderSettings(BaseSettings):
    """API-only model secret boundary, intentionally absent from general Settings."""

    model_config = SettingsConfigDict(
        env_prefix="SECOND_BRAIN_ANSWER_",
        env_file=LOCAL_ENV_FILE,
        extra="ignore",
    )

    api_key: SecretStr | None = None
    generation_model: str = "grounded-answer"


@lru_cache(maxsize=1)
def get_answer_provider_settings() -> AnswerProviderSettings:
    return AnswerProviderSettings()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


@lru_cache(maxsize=1)
def get_worker_settings() -> WorkerSettings:
    return WorkerSettings()
