"""
This module defines all Exceptions for GDetect.
GDetectError is for all external calls.
All other exceptions are for internal use.
"""


class GDetectError(Exception):
    """global error for external return"""

    message = ""

    def __init__(self, message: str = ""):
        self.message = message

    def __str__(self) -> str:
        if self.message != "":
            return f"{self.__doc__}: {self.message}"
        return self.__doc__


class NoAuthenticationTokenError(GDetectError):
    """No authentication token provided"""


class BadAuthenticationTokenError(GDetectError):
    """Bad authentication token provided"""


class NoURLError(GDetectError):
    """No URL to API provided"""


class UnauthorizedAccessError(GDetectError):
    """Access to API is unauthorized"""


class BadUUIDError(GDetectError):
    """Bad UUID value"""


class BadSHA256Error(GDetectError):
    """Bad SHA256 value"""


class MissingTokenError(GDetectError):
    """Missing token field in result"""


class MissingSIDError(GDetectError):
    """Missing file sid field in result"""


class MissingResponseError(GDetectError):
    """Missing response from api client"""


class ResultNotFoundError(GDetectError):
    """Result not found"""


class TooManyRequestsError(GDetectError):
    """Too many requests"""


class InternalServerError(GDetectError):
    """Internal server error"""


class GDetectTimeoutError(GDetectError):
    """Timeout during API call"""
