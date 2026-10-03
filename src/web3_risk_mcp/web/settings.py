"""Settings for the web app. Like the MCP server, it reads environment
variables or a `.env` file. See `.env.example`."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class WebSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Where to listen. Render and most hosts set PORT for you.
    web_host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)

    # How long a finished check is reused before running it again, in seconds.
    # Checks where a data source failed are kept for one minute only.
    web_result_cache_seconds: int = Field(default=600, ge=0)

    # Limits that protect the free API keys. Only new checks count; answers
    # from the cache are free.
    web_checks_per_minute: int = Field(default=6, ge=1)  # per visitor IP
    web_checks_per_hour: int = Field(default=40, ge=1)  # per visitor IP
    web_checks_per_day: int = Field(default=1500, ge=1)  # all visitors together
    web_max_parallel_checks: int = Field(default=3, ge=1)

    # The request header that holds the visitor's real IP, set by the host's
    # proxy. On Render this is "true-client-ip". Empty means "use the address
    # of the connection", which is right when nothing sits in front of the app.
    web_client_ip_header: str = ""

    # Address of the RiskAttestation contract on Arc, once you have deployed
    # it. Empty hides the "Save this check on Arc" button.
    attestation_contract: str = ""
