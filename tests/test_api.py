import urllib

import pytest
import requests
from gdetect import exceptions
from gdetect.api import Client
from gdetect.consts import WAIT_MIN_VALUE, WAIT_MAX_VALUE
from .mock import (
    mock_request_analysis_in_progress,
    mock_request_custom,
    mock_request_invalid_200,
    mock_request_too_many_request,
    mock_request,
    mock_request_nonexisting_resource,
    mock_request_invalid_file,
    mock_request_502,
    mock_csv_export,
    make_capturing_mock,
)


# file used for test purposes, it only have to exists
TEST_FILE = urllib.__file__
TEST_URL = "https://gmalware.domain.tld"
TEST_TOKEN = "01234567-01234567-01234567-01234567-01234567"


def get_api_client():
    """Return an api client.

    Returns:
        Client: api client
    """
    client = Client(TEST_URL, TEST_TOKEN)
    client.verify = False
    return client


def test_bad_url():
    """Test client setup with no url"""
    with pytest.raises(Exception):
        client = Client("tcp://gmalware.fr", TEST_TOKEN)
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_no_token_given(monkeypatch: pytest.MonkeyPatch):
    """Test client set up with no token."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.NoAuthenticationTokenError):
        client = Client(TEST_URL, "")
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_int_token_given(monkeypatch: pytest.MonkeyPatch):
    """Test client set up with int token."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.GDetectError):
        client = Client(TEST_URL, 1)
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )
    with pytest.raises(exceptions.BadAuthenticationTokenError):
        client = Client(TEST_URL, 1)
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_bad_length_token_given(monkeypatch: pytest.MonkeyPatch):
    """Test client set up with bad length token (!=44)."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.BadAuthenticationTokenError):
        client = Client(TEST_URL, "89abtacf-9458e74b")
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_bad_char_token_given(monkeypatch: pytest.MonkeyPatch):
    """Test client set up with bad char inside it (!= 0123456789abcdef-)."""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(exceptions.BadAuthenticationTokenError):
        client = Client(TEST_URL, "ttabtacf-9458e74b-06ca9e93-a285e90c-0a6bceb6")
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_push_no_file(monkeypatch: pytest.MonkeyPatch):
    """Expected a none result (+logging)"""
    monkeypatch.setattr(requests, "request", mock_request)
    with pytest.raises(FileNotFoundError):
        client = get_api_client()
        client.push("")


def test_push_elf_malware(monkeypatch: pytest.MonkeyPatch):
    """Expected an id as result"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    id_file = client.push(
        TEST_FILE,
        tags="elf",
        description="this is an elf malware.",
    )
    assert isinstance(id_file, str)


def test_push_quota_exceeded(monkeypatch: pytest.MonkeyPatch):
    """Expected an error 429"""
    monkeypatch.setattr(requests, "request", mock_request_too_many_request)
    with pytest.raises(exceptions.TooManyRequestsError):
        client = get_api_client()
        client.push(
            TEST_FILE,
            tags="elf",
            description="this is an elf malware.",
        )


def test_push_with_password(monkeypatch: pytest.MonkeyPatch):
    """Test that push with pwd is working"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    id_file = client.push(TEST_FILE, archive_password="toto")
    assert isinstance(id_file, str)


def test_retrieve_analysis_result_by_uuid(
    monkeypatch: pytest.MonkeyPatch, uuid="eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
):
    """Test file's info retrieved by uuid."""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.get_by_uuid(uuid)
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_retrieve_analysis_result_empty_uuid(monkeypatch: pytest.MonkeyPatch, uuid=""):
    """Test retrieving analysis result with empty uuid."""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client.get_by_uuid(uuid)


def test_search_sha256_empty(monkeypatch: pytest.MonkeyPatch, sha256=""):
    """Test search with empty sha26"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    with pytest.raises(exceptions.BadSHA256Error):
        client = get_api_client()
        client.get_by_sha256(sha256)


def test_search_sha256_inexisting(
    monkeypatch: pytest.MonkeyPatch,
    sha256="aaaad6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
):
    """Test file research with non existing sha256"""
    monkeypatch.setattr(requests, "request", mock_request_nonexisting_resource)
    with pytest.raises(exceptions.ResultNotFoundError):
        client = get_api_client()
        client.get_by_sha256(sha256)


def test_search_sha256_invalid(
    monkeypatch: pytest.MonkeyPatch,
    sha256="this_is_not_a_sha256",
):
    """Test file research with invalid sha256"""
    monkeypatch.setattr(requests, "request", mock_request_invalid_file)
    with pytest.raises(exceptions.BadSHA256Error):
        client = get_api_client()
        client.get_by_sha256(sha256)


def test_retrieve_analysis_result_by_sha256(
    monkeypatch: pytest.MonkeyPatch,
    sha256="7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
):
    """Test file research by sha256"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.get_by_sha256(sha256)
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_send_binary_and_wait_result_at_once(monkeypatch: pytest.MonkeyPatch):
    """Test waiting for a binary that has just been sent"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.waitfor(TEST_FILE)
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_send_and_wait_with_password(monkeypatch: pytest.MonkeyPatch):
    """Test that waitfor with pwd is working"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.waitfor(TEST_FILE, archive_password="toto")
    if "is_malware" not in result:
        pytest.fail("result is not the expected JSON")


def test_extract_url_token_view_empty():
    """Test url token view extraction with empty token"""
    client = get_api_client()
    with pytest.raises(exceptions.MissingTokenError):
        client.extract_url_token_view({})


def test_extract_url_token_view(monkeypatch: pytest.MonkeyPatch):
    """Test url token view extraction"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.waitfor(
        TEST_FILE,
        tags="elf",
        description="this is an elf malware.",
    )
    url = client.extract_url_token_view(result)
    assert url == urllib.parse.urljoin(
        client.base_url,
        f"/expert/en/analysis-redirect/{mock_request().json()['token']}",
    )


def test_extract_url_expert_view_empty_sid():
    """Test url expert view extraction with empty sid"""
    client = get_api_client()
    with pytest.raises(exceptions.MissingSIDError):
        client.extract_expert_url({})


def test_extract_url_expert_view(monkeypatch: pytest.MonkeyPatch):
    """Test url expert view extraction"""
    monkeypatch.setattr(requests, "request", mock_request)
    client = get_api_client()
    result = client.waitfor(
        TEST_FILE,
        tags="elf",
        description="this is an elf malware.",
    )
    url = client.extract_expert_url(result)
    assert url == urllib.parse.urljoin(
        client.base_url,
        f"/expert/en/analysis/advanced/{mock_request().json()['sid']}",
    )


def test_send_binary_and_wait_result_with_timeout(monkeypatch: pytest.MonkeyPatch):
    """Test waiting for a binary that has just been sent"""
    monkeypatch.setattr(requests, "request", mock_request_analysis_in_progress)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectTimeoutError):
        client.waitfor(TEST_FILE, pull_time=0.05, timeout=0.1)


def test_invalid_response_from_server_waitfor(monkeypatch: pytest.MonkeyPatch):
    """Test receiving an invalid response from the server"""
    monkeypatch.setattr(requests, "request", mock_request_502)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client.waitfor(TEST_FILE, pull_time=0.05, timeout=0.1)


def test_invalid_response_from_server_push(monkeypatch: pytest.MonkeyPatch):
    """Test receiving an invalid response from the server"""
    monkeypatch.setattr(requests, "request", mock_request_invalid_200)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client.push(TEST_FILE)
    monkeypatch.setattr(requests, "request", mock_request_custom(200, "test", True))
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client.push(TEST_FILE)
    monkeypatch.setattr(requests, "request", mock_request_custom(200, {"test": True}, True))
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client.push(TEST_FILE)


def test_gdetect_error():
    """Test custom gdetect errors"""
    exc = exceptions.BadSHA256Error("custom message")
    assert str(exc) == "Bad SHA256 value: custom message"


def test_get_status(monkeypatch: pytest.MonkeyPatch):
    """Test getting status for a profile"""
    monkeypatch.setattr(
        requests,
        "request",
        mock_request_custom(
            200,
            {
                "daily_quota": 2,
                "available_daily_quota": 0,
                "cache": False,
                "estimated_analysis_duration": 0,
            },
            True,
        ),
    )
    client = get_api_client()
    status = client.get_status()
    assert status.daily_quota == 2
    assert status.available_daily_quota == 0
    assert status.cache is False
    assert status.estimated_analysis_duration == 0

    # test with different values
    result_status = {
        "daily_quota": 1000,
        "available_daily_quota": 147,
        "cache": True,
        "estimated_analysis_duration": 9642,
    }
    monkeypatch.setattr(
        requests,
        "request",
        mock_request_custom(
            200,
            {
                "daily_quota": 1000,
                "available_daily_quota": 147,
                "cache": True,
                "estimated_analysis_duration": 9642,
            },
            True,
        ),
    )
    client = get_api_client()
    status = client.get_status()
    assert status.daily_quota == 1000
    assert status.available_daily_quota == 147
    assert status.cache is True
    assert status.estimated_analysis_duration == 9642
    assert status.to_dict() == result_status


def test_export_bad_format():
    """Test bad export format raises an error"""
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    client = get_api_client()
    with pytest.raises(exceptions.BadExportFormatError):
        client.export_result(uuid, format="docx", layout="")


def test_export_bad_layout():
    """Test bad export layout raises an error"""
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    client = get_api_client()
    with pytest.raises(exceptions.BadLayoutError):
        client.export_result(uuid, format="csv", layout="toto")


def test_export_ok(monkeypatch: pytest.MonkeyPatch):
    """Test export works"""
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    monkeypatch.setattr(requests, "request", mock_csv_export)
    client = get_api_client()
    export = client.export_result(uuid, format="csv", layout="en")
    assert isinstance(export, bytes)
    assert "Verdict,Score,Family,Filename,Submission date,User,Services list,Human filesize,SHA256" in export.decode(
        "utf-8"
    )


def test_export_server_error(monkeypatch: pytest.MonkeyPatch):
    """Test server error on export"""
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    monkeypatch.setattr(requests, "request", mock_request_502)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectError):
        client.export_result(uuid, format="csv", layout="fr")



def test_check_wait_none_raises():
    """None raises BadWaitValueError."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(None)


def test_check_wait_valid_values():
    """Integer values from WAIT_MIN_VALUE to WAIT_MAX_VALUE inclusive are valid."""
    client = get_api_client()
    mid = (WAIT_MIN_VALUE + WAIT_MAX_VALUE) // 2
    for value in [WAIT_MIN_VALUE, mid, WAIT_MAX_VALUE]:
        client._check_wait(value)


def test_check_wait_zero_valid():
    """Zero is a valid wait value."""
    client = get_api_client()
    client._check_wait(0)


def test_check_wait_negative_raises():
    """Negative values raise BadWaitValueError."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(-1)


def test_check_wait_above_max_raises():
    """WAIT_MAX_VALUE + 1 raises BadWaitValueError."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(WAIT_MAX_VALUE + 1)


def test_check_wait_far_above_max_raises():
    """Values far above WAIT_MAX_VALUE raise BadWaitValueError."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(WAIT_MAX_VALUE + 100)


def test_check_wait_float_raises():
    """Float raises BadWaitValueError."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(1.5)


def test_check_wait_string_raises():
    """String raises BadWaitValueError."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait("10")


def test_check_wait_bool_raises():
    """Bool raises BadWaitValueError (bool is a subclass of int in Python)."""
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(True)
    with pytest.raises(exceptions.BadWaitValueError):
        client._check_wait(False)



def test_get_by_uuid_with_wait(monkeypatch: pytest.MonkeyPatch):
    """When wait is set, the wait param is passed in the HTTP request."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    client = get_api_client()
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    client.get_by_uuid(uuid, wait=10)
    assert len(captured_calls) == 1
    params = captured_calls[0]["kwargs"].get("params", {})
    assert params.get("wait") == 10


def test_get_by_uuid_without_wait(monkeypatch: pytest.MonkeyPatch):
    """When wait is 0 (default), no wait param is sent in the HTTP request."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    client = get_api_client()
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    client.get_by_uuid(uuid)
    assert len(captured_calls) == 1
    params = captured_calls[0]["kwargs"].get("params", {})
    assert "wait" not in params


def test_get_by_uuid_with_invalid_wait(monkeypatch: pytest.MonkeyPatch):
    """Invalid wait raises BadWaitValueError before making HTTP request."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    client = get_api_client()
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    with pytest.raises(exceptions.BadWaitValueError):
        client.get_by_uuid(uuid, wait=-1)
    assert len(captured_calls) == 0


def test_get_by_uuid_timeout_adjusted_for_wait(monkeypatch: pytest.MonkeyPatch):
    """When wait is set, HTTP timeout is at least wait + 10."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    client = get_api_client()
    uuid = "eff8b042-3e70-4ea3-8f83-f9e67c217d3f"
    client.get_by_uuid(uuid, wait=25)
    timeout = captured_calls[0]["kwargs"].get("timeout")
    assert timeout >= 25 + 10



def test_waitfor_with_wait_param(monkeypatch: pytest.MonkeyPatch):
    """When wait is set, get_by_uuid receives wait and time.sleep is not called."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    sleep_calls = []
    monkeypatch.setattr("gdetect.api.time.sleep", lambda s: sleep_calls.append(s))
    client = get_api_client()
    result = client.waitfor(TEST_FILE, wait=10)
    assert result["done"] is True
    # sleep must NOT be called when wait is set
    assert len(sleep_calls) == 0
    # The get_by_uuid call (second request) must include the wait param
    get_calls = [c for c in captured_calls if "results" in str(c["args"])]
    assert len(get_calls) >= 1
    params = get_calls[0]["kwargs"].get("params", {})
    assert params.get("wait") == 10


def test_waitfor_without_wait_param(monkeypatch: pytest.MonkeyPatch):
    """When wait is 0 (default), time.sleep is called between polls."""
    monkeypatch.setattr(requests, "request", mock_request_analysis_in_progress)
    sleep_calls = []
    monkeypatch.setattr("gdetect.api.time.sleep", lambda s: sleep_calls.append(s))
    client = get_api_client()
    with pytest.raises(exceptions.GDetectTimeoutError):
        client.waitfor(TEST_FILE, pull_time=0.05, timeout=0.1)
    # sleep MUST be called when wait is 0
    assert len(sleep_calls) > 0


def test_waitfor_reader_with_wait_param(monkeypatch: pytest.MonkeyPatch):
    """waitfor_reader passes wait to get_by_uuid and skips sleep."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    sleep_calls = []
    monkeypatch.setattr("gdetect.api.time.sleep", lambda s: sleep_calls.append(s))
    client = get_api_client()
    import urllib
    with open(urllib.__file__, "rb") as f:
        result = client.waitfor_reader("test.py", f, wait=5)
    assert result["done"] is True
    assert len(sleep_calls) == 0
    get_calls = [c for c in captured_calls if "results" in str(c["args"])]
    assert len(get_calls) >= 1
    params = get_calls[0]["kwargs"].get("params", {})
    assert params.get("wait") == 5


def test_waitfor_with_wait_timeout(monkeypatch: pytest.MonkeyPatch):
    """Overall timeout still applies even when wait is set."""
    monkeypatch.setattr(requests, "request", mock_request_analysis_in_progress)
    monkeypatch.setattr("gdetect.api.time.sleep", lambda s: None)
    client = get_api_client()
    with pytest.raises(exceptions.GDetectTimeoutError):
        client.waitfor(TEST_FILE, wait=1, timeout=0.0)


def test_waitfor_with_wait_invalid(monkeypatch: pytest.MonkeyPatch):
    """Invalid wait value raises BadWaitValueError before any request."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    client = get_api_client()
    with pytest.raises(exceptions.BadWaitValueError):
        client.waitfor(TEST_FILE, wait=-1)
    assert len(captured_calls) == 0
