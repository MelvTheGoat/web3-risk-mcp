"""Client for the GoPlus Security API.

GoPlus runs automated security checks on tokens and addresses. For a token
it reports things like "is this a honeypot" (a token you can buy but never
sell) and "can the owner mint new tokens". For an address it reports links
to known crimes such as phishing or money laundering.

GoPlus works without a key. With an app key and secret you get higher limits.

Docs: https://docs.gopluslabs.io
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.http import HttpSource
from web3_risk_mcp.errors import SourceError

BASE_URL = "https://api.gopluslabs.io/api/v1"
NAME = "GoPlus"

# GoPlus answers HTTP 200 and puts its own status in "code".
# 1 means OK. 2 means "partial data" (still useful). Anything else is an error.
_OK_CODES = {1, 2}
_RATE_LIMIT_CODES = {4029}


def _validate(body: Any) -> None:
    if not isinstance(body, dict):
        raise SourceError(NAME, "Unexpected response shape.")
    code = body.get("code")
    if code in _OK_CODES:
        return
    message = body.get("message") or "unknown error"
    if code in _RATE_LIMIT_CODES or "too many" in str(message).lower():
        raise SourceError(NAME, f"Rate limit reached: {message}", retryable=True)
    raise SourceError(NAME, f"Request failed (code {code}): {message}")


def sign(app_key: str, app_secret: str, timestamp: int) -> str:
    """GoPlus signs token requests with sha1(app_key + time + app_secret)."""
    return hashlib.sha1(f"{app_key}{timestamp}{app_secret}".encode()).hexdigest()


class GoPlusClient:
    """Read-only calls to GoPlus."""

    def __init__(
        self, http: HttpSource, app_key: str | None = None, app_secret: str | None = None
    ) -> None:
        self.http = http
        self.app_key = app_key
        self.app_secret = app_secret
        self._token: str | None = None
        self._token_expires_at = 0.0

    async def _headers(self) -> dict[str, str]:
        if not (self.app_key and self.app_secret):
            return {}
        if self._token and time.time() < self._token_expires_at - 60:
            return {"Authorization": self._token}
        now = int(time.time())
        body = await self.http.request_json(
            "POST",
            f"{BASE_URL}/token",
            json_body={
                "app_key": self.app_key,
                "sign": sign(self.app_key, self.app_secret, now),
                "time": now,
            },
            validate=_validate,
            use_cache=False,
        )
        result = body.get("result") or {}
        token = result.get("access_token")
        if not token:
            raise SourceError(NAME, "Could not get an access token. Check your GoPlus keys.")
        self._token = token
        self._token_expires_at = time.time() + float(result.get("expires_in") or 3600)
        return {"Authorization": token}

    async def token_security(self, chain: Chain, token: str) -> dict[str, Any] | None:
        """Security report for one token contract, or None if GoPlus has no data."""
        body = await self.http.request_json(
            "GET",
            f"{BASE_URL}/token_security/{chain.chain_id}",
            params={"contract_addresses": token},
            headers=await self._headers(),
            validate=_validate,
        )
        result = body.get("result") or {}
        # Keys are addresses; GoPlus uses lower case but we do not rely on it.
        for key, value in result.items():
            if key.lower() == token.lower():
                return value or None
        return None

    async def address_security(self, chain: Chain, address: str) -> dict[str, Any]:
        """Known-bad labels for an address (phishing, mixer, sanctioned, and so on)."""
        body = await self.http.request_json(
            "GET",
            f"{BASE_URL}/address_security/{address}",
            params={"chain_id": chain.chain_id},
            headers=await self._headers(),
            validate=_validate,
        )
        return body.get("result") or {}
