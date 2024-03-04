# -*- coding: utf-8 -*-
import os
import pytest
import requests
from click.testing import CliRunner
from gdetect.cli import gdetect
from .mock import mock_request, mock_request_custom
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
    return CliRunner(mix_stderr=False)


def test_empty_run(runner: CliRunner):
    """Test empty run of the cli."""
    result = runner.invoke(gdetect, [""])
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


def test_get_existing_result_by_uuid(
    runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"
):
    """Test get of existing result by file uuid"""
    result = runner.invoke(gdetect, f"--insecure get {uuid}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_get_existing_result_by_uuid_and_urls(
    runner: CliRunner, uuid="9d488d01-23d5-4b9f-894e-c920ea732603"
):
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


def test_params(runner: CliRunner):
    """"""
    result = runner.invoke(
        gdetect,
        '--insecure --no-cache --password "toto" --debug '
        "--token=01234567-01234567-01234567-01234567-01234567 "
        "--url=http://test.test waitfor --tag=test_tag {TEST_FILE}",
    )
    assert result.exit_code == 1
