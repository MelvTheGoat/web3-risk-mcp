"""Error types with messages written for people, not machines."""


class Web3RiskError(Exception):
    """Base class for every error this project raises on purpose."""


class InvalidInputError(Web3RiskError):
    """The caller gave us something we cannot use, like a bad address."""


class SourceError(Web3RiskError):
    """A data source (an API or RPC endpoint) failed.

    `source` names the service, so a report can say exactly what is missing.
    `retryable` tells the HTTP layer whether trying again might help.
    """

    def __init__(self, source: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(f"{source}: {message}")
        self.source = source
        self.message = message
        self.retryable = retryable
