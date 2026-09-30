"""web3-risk-mcp: a read-only MCP server that checks wallets, tokens, and contracts for risk."""

from importlib.metadata import PackageNotFoundError, version

try:
    # The version lives in one place: pyproject.toml.
    __version__ = version("web3-risk-mcp")
except PackageNotFoundError:  # running from a source folder that was never installed
    __version__ = "0.0.0"
