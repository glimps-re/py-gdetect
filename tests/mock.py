"""
This file includes all test mocks
"""

from typing import Any
import requests


class MockRequest:
    """Mock a request to a file"""

    status_code = 200
    ok = True
    _json: dict = {
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
    _content: bytes = b""

    @property
    def content(self) -> bytes:
        """Return content of response"""
        return self._content

    def json(self) -> dict:
        """Return json encoded information about the file

        Returns:
            (dict): json encoded file's information.
        """
        return self._json


class MockResourceDoesNotExist(MockRequest):
    """Mock a request with 404 http status code
    (resource does not exist)"""

    ok = False
    status_code = 404
    _json = {"status": False, "error": "file not found"}


class MockResourceInvalidFile(MockRequest):
    """Mock a request with 400 status code (invalid file in our case)"""

    ok = False
    status_code = 400
    _json = {
        "status": False,
        "error": "bad request",
        "details": [{"file": "file is required"}],
    }


class MockTooManyRequests(MockRequest):
    """Mock a request with 429 status code (quota exceeded)"""

    ok = False
    status_code = 429
    _json = {"status": False, "error": "quota exceeded, try again in 24h"}


class MockAnalysisInProgress(MockRequest):
    """Mock a request for an analysis in progress"""

    ok = True
    status_code = 200
    _json = {
        "uuid": "9d488d01-23d5-4b9f-894e-c920ea732603",
        "sha256": "7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
        "sha1": "e0b77bdd78bf3215221298475c88fb23e4e84f98",
        "md5": "e1c080be1a748d69246ad9c766ad8809",
        "done": False,
        "timestamp": 0,
        "filetype": "elf",
        "size": 24728,
        "filenames": ["sample1"],
        "files": [],
        "sid": "7UZy0tbWPSTdNfkzKSW5gS",
    }


class Mock502(MockRequest):
    """Mock a 502 response from the server"""

    status_code = 502
    ok = False

    def json(self):
        raise requests.exceptions.JSONDecodeError("error", "error doc", 1)


class MockCsvExport(MockRequest):
    """Mock result of an CSV export"""

    _content = bytes(
        """Verdict,Score,Family,Filename,Submission date,User,Services list,Human filesize,SHA256
malicious,1000,"[""formbook""]",file1,2024-11-07T10:21:18.094535Z,totoplop,"[""SignatureAvira""]",862.0 KiB,66bf8be06f87343143d379706b4b151adc3e555c6efabf7fdd84d07b5a1b1d38'""",
        "utf-8",
    )


def mock_csv_export(*args, **kwargs):
    """Return successfull csv export"""
    return MockCsvExport()


def mock_request(*args, **kwargs):
    """Return json encoded mock request."""
    return MockRequest()


def mock_request_nonexisting_resource(*args, **kwargs):
    """Return http 404 mock request."""
    return MockResourceDoesNotExist()


def mock_request_invalid_file(*args, **kwargs):
    """Return http 400 mock request"""
    return MockResourceInvalidFile()


def mock_request_too_many_request(*args, **kwargs):
    """Return http 429 mock request"""
    return MockTooManyRequests()


def mock_request_analysis_in_progress(*args, **kwargs):
    """Return http 200 mock request"""
    return MockAnalysisInProgress()


def mock_request_502(*args, **kwargs):
    """Return http 502 mock request"""
    return Mock502()


def mock_request_invalid_200(*args, **kwargs):
    """Return http 502 mock request"""
    m = Mock502()
    m.status_code = 200
    m.ok = True
    return m


def mock_request_custom(status_code: int, json: Any, ok: bool):
    m = MockRequest()
    m.status_code = status_code
    m._json = json
    m.ok = ok

    def inner(*args, **kwargs):
        return m

    return inner
