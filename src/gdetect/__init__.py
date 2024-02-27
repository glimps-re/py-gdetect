from .api import Client
from .exceptions import (
    GDetectError,
    BadAuthenticationTokenError,
    BadSHA256Error,
    BadUUIDError,
)


__doc__ = Client.__doc__
__all__ = [
    "Client",
    "GDetectError",
    "BadAuthenticationTokenError",
    "BadSHA256Error",
    "BadUUIDError",
]
