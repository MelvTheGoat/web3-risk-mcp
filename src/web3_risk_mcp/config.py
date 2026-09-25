"""Settings for the server.

All settings come from environment variables or a `.env` file.
See `.env.example` for the full list with explanations.
"""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Every setting the server reads, with safe defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API keys. SecretStr hides the value if the settings object is printed or logged.
    etherscan_api_key: SecretStr | None = None
    goplus_app_key: SecretStr | None = None
    goplus_app_secret: SecretStr | None = None

    # Optional custom RPC endpoints. Empty means "use the public default".
    rpc_url_ethereum: str | None = None
    rpc_url_base: str | None = None
    rpc_url_arbitrum: str | None = None
    rpc_url_polygon: str | None = None
    rpc_url_bsc: str | None = None

    # Network behaviour.
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    cache_ttl_seconds: int = Field(default=300, ge=0)

    # Requests per second we allow ourselves to send to each source.
    # These stay under each provider's free-plan limits.
    etherscan_requests_per_second: float = Field(default=3.0, gt=0)
    goplus_requests_per_second: float = Field(default=0.5, gt=0)
    dexscreener_requests_per_second: float = Field(default=4.0, gt=0)
    rpc_requests_per_second: float = Field(default=10.0, gt=0)

    log_level: str = "INFO"

    # Only used by the streamable HTTP transport.
    http_host: str = "127.0.0.1"
    http_port: int = Field(default=8000, ge=1, le=65535)

    def rpc_override(self, chain_key: str) -> str | None:
        """Return the custom RPC URL for a chain, if the user set one."""
        value = getattr(self, f"rpc_url_{chain_key}", None)
        return value or None

    @staticmethod
    def secret(value: SecretStr | None) -> str | None:
        """Unwrap a secret. Empty strings count as "not set"."""
        if value is None:
            return None
        raw = value.get_secret_value().strip()
        return raw or None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings once and reuse them."""
    return Settings()
