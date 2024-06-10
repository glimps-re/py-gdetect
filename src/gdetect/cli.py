#!/usr/bin/env python3
"""
cli: the CLI client for GLIMPS detect.

This client aims to use GLIMPS detect API inside a shell.
`send` is the default command ; you can omit it to simplify uses.
Show `--help` to see how to use it.

>>> python3 -m gdetect --help
Usage: python -m gdetect [OPTIONS] COMMAND [ARGS]...

Options:
  --url TEXT    url to GLIMPS Detect API
  --token TEXT  authentication token
  --password TEXT passord used to extract archive
  --insecure    disable HTTPS check
  --no-cache    submit file even if a result already exists
  --help        Show this message and exit.

Commands:
  get      get result for given uuid.
  search   search a file with given sha256.
  send     send file to API.
  status   Get Detect profile status
  waitfor  send a file and wait for the result.
"""

from dataclasses import dataclass
from functools import wraps
import logging
import os
from typing import List, Optional

import click
import rich
from click_default_group import DefaultGroup
from rich.console import Console
from requests.exceptions import MissingSchema

from . import log
from .api import Client
from .exceptions import (
    GDetectError,
    MissingSIDError,
    MissingTokenError,
)

# initialize rich Console for pretty print
console = Console()
error_console = Console(stderr=True, style="bold red")


@dataclass
class GDetectContext:
    """
    GDetect CLI context
    """

    logger: logging.Logger = log.get_logger()
    url: str = ""  # os.getenv("API_URL")
    token: str = ""  # os.getenv("API_TOKEN")
    archive_password: str = ""
    insecure: bool = False
    no_cache: bool = False
    client: Client = None

    def __init__(self):
        self.url = os.getenv("API_URL")
        self.token = os.getenv("API_TOKEN")


def catch_exceptions(func):
    """decorator to catch exceptions and raise a ClickException"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except MissingSchema as exc:
            raise click.ClickException(
                "Invalid or no URL provided to reach GMalware detect API"
            ) from exc
        except GDetectError as e:
            raise click.ClickException(e) from e

    return wrapper


@click.group(cls=DefaultGroup, default="", default_if_no_args=False)
@click.option("--url", default="", help="url to GLIMPS Detect API")
@click.option("--token", default="", help="authentication token")
@click.option("--password", default="", help="password used to extract archive")
@click.option("--insecure", is_flag=True, help="bypass HTTPS check")
@click.option(
    "--no-cache",
    "nocache",
    is_flag=True,
    help="submit file even if a result already exists",
)
@click.option("--debug", is_flag=True, help="print debug strings")
@click.pass_context
@catch_exceptions
def gdetect(
    ctx: click.Context = None,
    url: str = "",
    token: str = "",
    password: str = "",
    insecure: bool = False,
    nocache: bool = False,
    debug: bool = False,
):
    """CLI for GLIMPS detect"""
    ctx.ensure_object(GDetectContext)

    obj: GDetectContext = ctx.obj

    if debug is True:
        obj.logger.setLevel(logging.DEBUG)

    if token != "":
        obj.token = token
    if url != "":
        obj.url = url
    if password != "":
        obj.archive_password = password

    obj.client = Client(url=obj.url, token=obj.token)

    if insecure:
        error_console.print("untrusted: SSL verification disabled")
        obj.insecure = insecure
        obj.client.verify = not insecure
    if nocache:
        obj.no_cache = nocache


@gdetect.command("send")
@click.pass_obj
@click.argument("filename")
@click.option("-t", "--tag", multiple=True, help="tags to assign to the file.")
@click.option("-d", "--description", help="description of the file.")
@catch_exceptions
def send(
    obj: GDetectContext = None,
    filename: str = "",
    tag: str = "",
    description: str = "",
):
    """send file to API."""
    uuid = obj.client.push(
        filename,
        bypass_cache=obj.no_cache,
        tags=tag,
        description=description,
        archive_password=obj.archive_password,
    )
    console.print(uuid)


@gdetect.command("get")
@click.pass_obj
@click.argument("uuid")
@click.option("--retrieve-urls", is_flag=True, default=False, help="retrieve urls")
@catch_exceptions
def get(obj: GDetectContext = None, uuid: str = "", retrieve_urls: bool = False):
    """get result for given uuid."""
    result = obj.client.get_by_uuid(uuid)
    rich.print_json(data=result)
    if retrieve_urls:
        print_urls(result)


@gdetect.command("search")
@click.argument("sha256")
@click.option("--retrieve-urls", is_flag=True, help="retrieve urls")
@click.pass_obj
@catch_exceptions
def search(obj: GDetectContext = None, sha256: str = "", retrieve_urls: bool = False):
    """search a file with given sha256."""
    result = obj.client.get_by_sha256(sha256)
    rich.print_json(data=result)
    if retrieve_urls:
        print_urls(result)


@gdetect.command("waitfor")
@click.pass_obj
@click.argument("filename")
@click.option("--timeout", default=180, help="set a timeout in seconds")
@click.option("-t", "--tag", multiple=True, help="tags to assign to the file.")
@click.option("-d", "--description", help="description of the file.")
@click.option("--retrieve-urls", is_flag=True, help="retrieve urls")
@catch_exceptions
def waitfor(
    obj: GDetectContext = None,
    filename: str = "",
    timeout: int = 180,
    tag: Optional[List[str]] = None,
    description: str = "",
    retrieve_urls: bool = False,
):
    """send a file and wait for the result."""
    result = obj.client.waitfor(
        filename,
        bypass_cache=obj.no_cache,
        timeout=timeout,
        tags=tag,
        description=description,
        archive_password=obj.archive_password,
    )
    rich.print_json(data=result)
    if retrieve_urls:
        print_urls(result)


@click.pass_obj
def print_urls(obj: GDetectContext = None, result: object = None):
    """Print url for token and analysis view"""
    try:
        url_token_view = obj.client.extract_url_token_view(result)
        console.print("TOKEN VIEW URL: ", url_token_view)
    except MissingTokenError:
        pass

    try:
        url_expert_analyse = obj.client.extract_expert_url(result)
        console.print("ANALYSIS VIEW URL: ", url_expert_analyse)
    except MissingSIDError:
        pass


@gdetect.command("status")
@click.pass_obj
@catch_exceptions
def status(obj: GDetectContext = None):
    """Get Detect profile status"""
    result = obj.client.get_status()
    rich.print_json(data=result.to_dict())


if __name__ == "__main__":
    gdetect()
