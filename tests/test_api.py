import urllib

import pytest
import requests
from gdetect import exceptions
from gdetect.api import Client
from .mock import *


# file used for test purposes, it only have to exists
TEST_FILE = urllib.__file__
TEST_URL = "https://gmalware.domain.tld"
TEST_TOKEN = "978abce3-42af0258-c5dee9ad-85e6fb5e-a249b8a3"


def get_api_client():
    """Return an api client.

    Returns:
        Client: api client
    """
    client = Client(TEST_URL, TEST_TOKEN)
    client.verify = False
    return client


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


def test_bad_url():
    """Test client setup with no url"""

    with pytest.raises(exceptions.GDetectError):
        client = Client("tcp://gmalware.fr", TEST_TOKEN)
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )
    assert client.response.message == "the URL schema (e.g. http or https) is missing"


def test_no_token_given(monkeypatch):
    """Test client set up with no token."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.NoAuthenticateToken):
        client = Client(TEST_URL, "")
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_int_token_given(monkeypatch):
    """Test client set up with int token."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.GDetectError):
        client = Client(TEST_URL, 1)
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )
    with pytest.raises(exceptions.BadAuthenticationToken):
        client = Client(TEST_URL, 1)
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_bad_length_token_given(monkeypatch):
    """Test client set up with bad length token (!=44)."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.BadAuthenticationToken):
        client = Client(TEST_URL, "89abtacf-9458e74b")
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_bad_char_token_given(monkeypatch):
    """Test client set up with bad char inside it (!= 0123456789abcdef-)."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.BadAuthenticationToken):
        client = Client(TEST_URL, "ttabtacf-9458e74b-06ca9e93-a285e90c-0a6bceb6")
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_push_no_file(monkeypatch):
    """Expected a none result (+logging)"""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.GDetectError):
        client = get_api_client()
        client.push("")
    assert client.response.error.__class__ == FileNotFoundError


def test_push_elf_malware(monkeypatch):
    """Expected an id as result"""

    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    id_file = client.push(
        TEST_FILE,
        tags="elf",
        description="this is an elf malware.",
    )
    assert isinstance(id_file, str)


def test_push_quota_exceeded(monkeypatch):
    """Expected an error 429"""
    monkeypatch.setattr(requests, "request", mock_request_too_many_request)
    with pytest.raises(exceptions.GDetectError):
        client = get_api_client()
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )
    assert client.response.message == "too many requests"


def test_retrieve_analysis_result_by_uuid(
    monkeypatch, uuid="eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
):
    """Test file's info retrieved by uuid."""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.get_by_uuid(uuid)
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_retrieve_analysis_result_empty_uuid(monkeypatch, uuid=""):
    """Test file's info retrieved by uuid."""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    try:
        result = client.get_by_uuid(uuid)
        assert False
    except exceptions.GDetectError:
        assert True


def test_search_sha256_empty(monkeypatch, sha256=""):
    """Test search with empty sha26"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client = get_api_client()
        client.get_by_sha256(sha256)
    assert client.response.message == "SHA256 is empty"


def test_search_sha256_inexisting(
    monkeypatch,
    sha256="aaaad6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
):
    """Test file research with inexisting sha256"""
    monkeypatch.setattr(requests, "request", mock_request_nonexisting_resource)
    with pytest.raises(exceptions.GDetectError):
        client = get_api_client()
        client.get_by_sha256(sha256)
    assert client.response.message == "resource doesn't exist"


def test_search_sha256_invalid(
    monkeypatch,
    sha256="this_is_not_a_sha256",
):
    """Test file research with invalid sha256"""
    monkeypatch.setattr(requests, "request", mock_request_invalid_file)
    with pytest.raises(exceptions.GDetectError):
        client = get_api_client()
        client.get_by_sha256(sha256)
    assert client.response.message == "invalid file submitted"


def test_retrieve_analysis_result_by_sha256(
    monkeypatch,
    sha256="7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
):
    """Test file research by sha256"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.get_by_sha256(sha256)
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_send_binary_and_wait_result_at_once(monkeypatch):
    """Test waiting for a binary that has just been sent"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.waitfor(TEST_FILE)
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_extract_url_token_view(monkeypatch):
    """Test url token view extraction"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    client.push(
        TEST_FILE,
        tags="elf",
        description="this is an elf malware.",
    )
    url = client.extract_url_token_view()
    assert url == urllib.parse.urljoin(
        client.base_url,
        f"/expert/en/analysis-redirect/{mock_request().json()['token']}",
    )


def test_extract_url_expert_view(monkeypatch):
    """Test url token view extraction"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    client.push(
        TEST_FILE,
        tags="elf",
        description="this is an elf malware.",
    )
    url = client.extract_expert_url()
    assert url == urllib.parse.urljoin(
        client.base_url,
        f"/expert/en/analysis/advanced/{mock_request().json()['sid']}",
    )
