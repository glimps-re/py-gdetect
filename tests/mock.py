"""
This file includes all test mocks
"""


class MockRequest:
    """Mock a request to a file"""

    status_code = 200

    @staticmethod
    def json() -> dict:
        """Return json encoded information about the file

        Returns:
            (dict): json encoded file's information.
        """
        return {
            "uuid": "9d488d01-23d5-4b9f-894e-c920ea732603",
            "sha256": "7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
            "sha1": "e0b77bdd78bf3215221298475c88fb23e4e84f98",
            "md5": "e1c080be1a748d69246ad9c766ad8809",
            "ssdeep": "3:FEROlMk3/DXO2EXhIWAlvgulM4jIL2Q:FEROik3guWe9i4jIL2Q",
            "is_malware": True,
            "score": 3000,
            "done": True,
            "timestamp": 0,
            "filetype": "elf",
            "size": 24728,
            "filenames": ["sha256"],
            "files": [],
            "sid": "7UZy0tbWPSTdNfkzKSW5gS",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.XXX.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        }


class MockResourceDoesNotExist:
    """Mock a request with 404 http status code
    (resource does not exist)"""

    status_code = 404


class MockResourceInvalidFile:
    """Mock a request with 400 status code (invalid file in our case)"""

    status_code = 400


class MockTooManyRequests:
    """Mock a request with 429 status code (quota exceeded)"""

    status_code = 429


def mock_request(*args, **kwargs):
    """Return json encoded mock request."""
    return MockRequest()


def mock_request_nonexisting_resource(*args, **kwargs):
    """Return http 404 mock request."""
    return MockResourceDoesNotExist()


def mock_request_invalid_file(*args, **kwargs):
    """Return http 400 mock request"""
    return MockResourceInvalidFile


def mock_request_too_many_request(*args, **kwargs):
    """Return http 429 mock request"""
    return MockTooManyRequests
