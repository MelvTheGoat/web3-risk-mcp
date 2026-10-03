import logging

import pytest

from web3_risk_mcp import __version__
from web3_risk_mcp.__main__ import main
from web3_risk_mcp.config import setup_logging


def test_version_comes_from_package_metadata(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"web3-risk-mcp {__version__}"
    assert __version__ != "0.0.0"


def test_logging_never_writes_request_urls_that_may_hold_keys():
    setup_logging("DEBUG")
    # httpx logs full URLs at INFO, and Etherscan URLs contain the API key.
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    assert not logging.getLogger("httpcore").isEnabledFor(logging.INFO)
    assert logging.getLogger("httpx").isEnabledFor(logging.WARNING)
