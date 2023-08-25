# -*- coding: utf-8 -*-

"""
This module define all Exceptions for GDetect.
GDetectError is for all external call.
All other exceptions are for internal use.
"""


class GDetectError(Exception):
    """global error for external return"""


class NoAuthenticateToken(GDetectError):
    """no token to authentication exists"""


class BadAuthenticationToken(GDetectError):
    """given token has bad format"""


class NoURL(GDetectError):
    """no URL to API found"""


class UnauthorizedAccess(GDetectError):
    """access to API is unauthorized"""


class BadUUID(GDetectError):
    """given UUID is wrong"""


class BadSHA256(GDetectError):
    """given SHA256 hash is wrong"""


class MissingToken(GDetectError):
    """Missing token field in result"""


class MissingSID(GDetectError):
    """Missing file sid field in result"""


class MissingResponse(GDetectError):
    """Missing response from api client"""
