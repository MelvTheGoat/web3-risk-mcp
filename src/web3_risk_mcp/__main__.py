"""Command-line entry point.

Run with stdio (for Claude Desktop, Cursor, and most local clients):
    web3-risk-mcp

Run as a streamable HTTP server (for remote or shared use):
    web3-risk-mcp --transport http --port 8000
"""

from __future__ import annotations

import argparse
import logging
import sys

from web3_risk_mcp.config import get_settings
from web3_risk_mcp.server import create_server


def main(argv: list[str] | None = None) -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="web3-risk-mcp",
        description="Read-only MCP server that checks wallets, tokens, and contracts for risk.",
    )
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default=settings.http_host)
    parser.add_argument("--port", type=int, default=settings.http_port)
    args = parser.parse_args(argv)

    # Logs go to stderr. With stdio, stdout is reserved for MCP messages.
    logging.basicConfig(
        level=settings.log_level.upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    server = create_server()
    if args.transport == "http":
        server.run("streamable-http", host=args.host, port=args.port)
    else:
        server.run("stdio")


if __name__ == "__main__":
    main()
