"""Arc Safe Send: a small web app that runs the risk check before you send USDC.

It serves one page and one API call (POST /api/check). It uses the same
read-only checks as the MCP server. The server never sees a private key and
never signs anything: any payment is signed in the user's own browser wallet.

Install and run:
    pip install "web3-risk-mcp[web]"
    web3-risk-web --port 8080
"""
