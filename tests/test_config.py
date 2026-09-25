from pydantic import SecretStr

from web3_risk_mcp.config import Settings


def test_defaults_work_without_any_env(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    settings = Settings(_env_file=None)
    assert settings.etherscan_api_key is None
    assert settings.http_max_retries == 3


def test_settings_read_from_environment(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "abc123")
    monkeypatch.setenv("RPC_URL_BASE", "https://example.org/rpc")
    settings = Settings(_env_file=None)
    assert Settings.secret(settings.etherscan_api_key) == "abc123"
    assert settings.rpc_override("base") == "https://example.org/rpc"
    assert settings.rpc_override("ethereum") is None


def test_secret_is_hidden_when_printed():
    settings = Settings(_env_file=None, etherscan_api_key=SecretStr("topsecret"))
    assert "topsecret" not in repr(settings)


def test_blank_secret_counts_as_missing():
    assert Settings.secret(SecretStr("   ")) is None
