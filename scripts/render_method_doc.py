"""Write docs/risk-method.md from the live rule table.

Run: uv run python scripts/render_method_doc.py
"""

from pathlib import Path

from web3_risk_mcp.method import scoring_method_markdown

TARGET = Path(__file__).resolve().parent.parent / "docs" / "risk-method.md"

if __name__ == "__main__":
    TARGET.write_text(scoring_method_markdown())
    print(f"Wrote {TARGET}")
