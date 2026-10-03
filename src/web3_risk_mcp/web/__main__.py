"""Start the Arc Safe Send web app.

    web3-risk-web                      # http://127.0.0.1:8080
    web3-risk-web --host 0.0.0.0 --port 10000

API keys and limits come from environment variables or a `.env` file.
"""

from __future__ import annotations

import argparse
import sys

from web3_risk_mcp.config import get_settings, setup_logging
from web3_risk_mcp.web.settings import WebSettings


def main(argv: list[str] | None = None) -> None:
    try:
        import uvicorn

        from web3_risk_mcp.web.app import create_app
    except ImportError:
        print(
            "The web app needs extra packages. Install them with:\n"
            '    pip install "web3-risk-mcp[web]"',
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    web = WebSettings()
    parser = argparse.ArgumentParser(
        prog="web3-risk-web", description="Arc Safe Send: check an address before you pay."
    )
    parser.add_argument("--host", default=web.web_host)
    parser.add_argument("--port", type=int, default=web.port)
    args = parser.parse_args(argv)

    setup_logging(get_settings().log_level)
    uvicorn.run(create_app(web), host=args.host, port=args.port, server_header=False)


if __name__ == "__main__":
    main()
