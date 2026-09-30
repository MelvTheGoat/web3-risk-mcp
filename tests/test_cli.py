import pytest

from web3_risk_mcp import __version__
from web3_risk_mcp.__main__ import main


def test_version_comes_from_package_metadata(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"web3-risk-mcp {__version__}"
    assert __version__ != "0.0.0"
