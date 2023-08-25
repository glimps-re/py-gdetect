# -*- coding: utf-8 -*-
import os
import pytest
import requests
from click.testing import CliRunner
from gdetect.cli import gdetect
from .mock import mock_request
from .test_api import TEST_FILE


def get_test_env(key: str) -> str:
    """setup URL and TOKEN env vars"""
    return {
        "API_TOKEN": "978abce3-42af0258-c5dee9ad-85e5fb5e-a249b8a2",
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
    assert result.exit_code == 0


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
    result = runner.invoke(gdetect, f"--insecure search {sha256}")
    assert result.exit_code == 0


def test_send_as_default_command(runner: CliRunner):
    """Test that send is the default command (thus no command is specified)."""
    result = runner.invoke(gdetect, f"--insecure {TEST_FILE}")
    assert result.exit_code == 0
    assert len(result.output) > 35


def test_send_binary_and_wait_for_result(runner: CliRunner):
    """Test binary sending waiting for the result."""
    result = runner.invoke(gdetect, f"--insecure --no-cache waitfor {TEST_FILE}")
    assert result.exit_code == 0
    assert len(result.output) > 35
