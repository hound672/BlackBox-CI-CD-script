import requests


class BlackBoxError(Exception):
    pass


class BlackBoxRequestError(BlackBoxError):
    pass


class BlackBoxUrlError(BlackBoxRequestError):
    pass


class BlackBoxConnectionError(BlackBoxUrlError):
    pass


class BlackBoxSSLError(BlackBoxConnectionError):
    pass


class BlackBoxInvalidUrlError(BlackBoxUrlError):
    pass


class BlackBoxHTTPError(BlackBoxRequestError):
    def __init__(
        self, *args: object, request: requests.Request, response: requests.Response
    ):
        self.request = request
        self.response = response
        super().__init__(*args)


class ScanResultError(Exception):
    """Report checks errors"""

    pass


class ScoreFailError(ScanResultError):
    pass


class ToolError(BlackBoxError):
    pass


class UrlParseError(ToolError, ValueError):
    pass
