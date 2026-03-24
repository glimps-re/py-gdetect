# -*- coding: utf-8 -*-
import os
import pytest
import requests
from click.testing import CliRunner
from gdetect.cli import gdetect
from .mock import mock_request, mock_request_custom, mock_csv_export, make_capturing_mock
from .test_api import TEST_FILE


def get_test_env(key: str) -> str:
    """setup URL and TOKEN env vars"""
    return {
        "API_TOKEN": "01234567-01234567-01234567-01234567-01234567",
        "API_URL": "http://localhost",
    }.get(key, os.environ.get(key))


@pytest.fixture(autouse=True)
def with_mock_request(monkeypatch):
    """replace requests.request with a mock"""
    monkeypatch.setattr(requests, "request", mock_request)


@pytest.fixture(autouse=True)
def with_api_env(monkeypatch):
    """set API_TOKEN and API_URL for test"""
    monkeypatch.setattr(os, "getenv", get_test_env)


@pytest.fixture
def runner():
    """define a CliRunner"""
    return CliRunner()


def test_empty_run(runner: CliRunner):
    """Test empty run of the cli."""
    result = runner.invoke(gdetect, None)
    assert result.exit_code == 2


def test_send_file_no_token(runner: CliRunner, monkeypatch):
    """Test file sending."""
    monkeypatch.setattr(os, "getenv", lambda x: "")
    result = runner.invoke(gdetect, f"--insecure send {TEST_FILE}")
    assert result.exit_code == 1


def test_send_file(runner: CliRunner):
    """Test file sending."""
    result = runner.invoke(gdetect, f"--insecure send {TEST_FILE}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_send_file_without_cache(runner: CliRunner):
    """Test file sending without any cache"""
    result = runner.invoke(gdetect, f"--insecure --no-cache send {TEST_FILE}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_send_file_with_tags(runner: CliRunner):
    """Test file sending with some tags"""
    result = runner.invoke(gdetect, f"--insecure send {TEST_FILE} -t tag1 --tag tag2")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_send_file_with_description(runner: CliRunner):
    """Test file sending with description."""
    result = runner.invoke(
        gdetect,
        f'--insecure send  --description "This is a description" {TEST_FILE}',
    )
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_send_file_with_password(runner: CliRunner):
    """Test file sending protected archive with password."""
    result = runner.invoke(
        gdetect,
        f'--insecure --password "toto" send {TEST_FILE}',
    )
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_get_existing_result_by_uuid(runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Test get of existing result by file uuid"""
    result = runner.invoke(gdetect, f"--insecure get {uuid}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_get_existing_result_by_uuid_and_urls(runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Test get of existing result by file uuid"""
    result = runner.invoke(gdetect, f"--insecure get {uuid} --retrieve-urls")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_get_existing_result_by_sha256(
    runner: CliRunner,
    sha256="7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
):
    """Test get of existing result by file sha256"""
    result = runner.invoke(gdetect, f"--insecure search --retrieve-urls {sha256}")
    assert result.exit_code == 0


def test_send_as_default_command(runner: CliRunner):
    """Test that send is the default command (thus no command is specified)."""
    result = runner.invoke(gdetect, f"--insecure {TEST_FILE}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_waitfor_file(runner: CliRunner):
    """Test file sending waiting for the result."""
    result = runner.invoke(gdetect, f"--insecure --no-cache waitfor {TEST_FILE}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_waitfor_file_no_url_to_retrieve(runner: CliRunner, monkeypatch: pytest.MonkeyPatch):
    """Test file sending waiting with no token or sid."""
    monkeypatch.setattr(
        requests,
        "request",
        mock_request_custom(
            200,
            {
                "uuid": "9d488d01-23d5-4b9f-894e-c920ea732603",
                "sha256": "7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99",
                "sha1": "e0b77bdd78bf3215221298475c88fb23e4e84f98",
                "md5": "e1c080be1a748d69246ad9c766ad8809",
                "done": True,
                "timestamp": 0,
                "filetype": "elf",
                "size": 24728,
                "filenames": ["sample1"],
                "files": [],
            },
            True,
        ),
    )
    result = runner.invoke(
        gdetect,
        f"--insecure --no-cache waitfor --retrieve-urls {TEST_FILE}",
    )
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_waitfor_file_with_password(runner: CliRunner):
    """Test file sending waiting for protected archive with password."""
    result = runner.invoke(
        gdetect,
        f'--insecure --no-cache --password "toto" waitfor {TEST_FILE}',
    )
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_status(runner: CliRunner, monkeypatch: pytest.MonkeyPatch):
    """Test get profile status"""
    monkeypatch.setattr(requests, "request", mock_request_custom(200, {}, True))
    result = runner.invoke(gdetect, "status")
    assert result.exit_code == 0


def test_export(runner: CliRunner, monkeypatch: pytest.MonkeyPatch):
    """Test export submission result"""
    uuid = "9d488d01-23d5-4b9f-894e-c920ea732603"
    monkeypatch.setattr(requests, "request", mock_csv_export)
    result = runner.invoke(gdetect, f"export {uuid} --format csv --layout en")
    assert result.exit_code == 0


def test_params(runner: CliRunner):
    """"""
    result = runner.invoke(
        gdetect,
        '--insecure --no-cache --password "toto" --debug '
        "--token=01234567-01234567-01234567-01234567-01234567 "
        "--url=http://test.test waitfor --tag=test_tag {TEST_FILE}",
    )
    assert result.exit_code == 1



def test_get_with_wait(runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Test get command with --wait option."""
    result = runner.invoke(gdetect, f"--insecure get --wait 10 {uuid}")
    assert result.exit_code == 0


def test_get_without_wait(runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Test get command without --wait option (backward compat)."""
    result = runner.invoke(gdetect, f"--insecure get {uuid}")
    assert result.exit_code == 0


def test_get_with_invalid_wait_value(runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Test get command with invalid --wait value raises error."""
    result = runner.invoke(gdetect, f"--insecure get --wait -1 {uuid}")
    assert result.exit_code == 1


def test_get_with_invalid_wait_type(runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Test get command with invalid --wait type fails at click level."""
    result = runner.invoke(gdetect, f"--insecure get --wait abc {uuid}")
    assert result.exit_code == 2


def test_waitfor_with_wait(runner: CliRunner):
    """Test waitfor command with --wait option."""
    result = runner.invoke(gdetect, f"--insecure --no-cache waitfor --wait 10 {TEST_FILE}")
    assert result.exit_code == 0


def test_waitfor_without_wait(runner: CliRunner):
    """Test waitfor command without --wait option (backward compat)."""
    result = runner.invoke(gdetect, f"--insecure --no-cache waitfor {TEST_FILE}")
    assert result.exit_code == 0



def test_cli_get_wait_end_to_end(runner: CliRunner, monkeypatch, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"):
    """Full CLI get --wait flow: verifies wait param reaches HTTP request."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    result = runner.invoke(gdetect, f"--insecure get --wait 15 {uuid}")
    assert result.exit_code == 0
    get_calls = [c for c in captured_calls if "results" in str(c["args"])]
    assert len(get_calls) == 1
    params = get_calls[0]["kwargs"].get("params", {})
    assert params.get("wait") == 15


def test_cli_get_no_wait_param_in_request(
    runner: CliRunner, monkeypatch, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"
):
    """When --wait is not given, no wait param is present in HTTP request."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    result = runner.invoke(gdetect, f"--insecure get {uuid}")
    assert result.exit_code == 0
    get_calls = [c for c in captured_calls if "results" in str(c["args"])]
    assert len(get_calls) == 1
    params = get_calls[0]["kwargs"].get("params", {})
    assert "wait" not in params


def test_cli_waitfor_wait_end_to_end(runner: CliRunner, monkeypatch):
    """Full CLI waitfor --wait flow: verifies wait param reaches HTTP request and no sleep."""
    capturing_mock, captured_calls = make_capturing_mock()
    monkeypatch.setattr(requests, "request", capturing_mock)
    sleep_calls = []
    monkeypatch.setattr("gdetect.api.time.sleep", lambda s: sleep_calls.append(s))
    result = runner.invoke(gdetect, f"--insecure --no-cache waitfor --wait 5 {TEST_FILE}")
    assert result.exit_code == 0
    get_calls = [c for c in captured_calls if "results" in str(c["args"])]
    assert len(get_calls) >= 1
    params = get_calls[0]["kwargs"].get("params", {})
    assert params.get("wait") == 5
    assert len(sleep_calls) == 0


def test_cli_waitfor_no_wait_sleeps(runner: CliRunner, monkeypatch):
    """When --wait is not given, time.sleep is called between polls."""
    from .mock import mock_request_analysis_in_progress

    monkeypatch.setattr(requests, "request", mock_request_analysis_in_progress)
    sleep_calls = []
    monkeypatch.setattr("gdetect.api.time.sleep", lambda s: sleep_calls.append(s))
    # Fake clock: returns 0 for a few calls (allowing polling + sleep), then
    # jumps past the timeout to stop the loop.
    timestamps = iter([0, 0, 0, 0, 200])
    monkeypatch.setattr("gdetect.api.time.time", lambda: next(timestamps, 200))
    result = runner.invoke(gdetect, f"--insecure --no-cache waitfor --timeout 180 {TEST_FILE}")
    assert result.exit_code == 1
    assert len(sleep_calls) > 0
