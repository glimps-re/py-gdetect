"""Exceptions for the GDetect client.

GDetectError is the base class. Subclasses represent specific error conditions
such as authentication failures, invalid inputs, and server errors.
"""

from .consts import EXPORT_LAYOUTS, EXPORT_FORMATS


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


class BadExportFormatError(GDetectError):
    __doc__ = f"Bad export format value (must be one of {EXPORT_FORMATS})"


class BadLayoutError(GDetectError):
    __doc__ = f"Bad layout value (must be one of {EXPORT_LAYOUTS})"


class BadWaitValueError(GDetectError):
    """Bad wait value (must be an integer between 0 and 59 inclusive)"""
