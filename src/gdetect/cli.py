#!/usr/bin/env python3
# *_* coding: utf-8 *_*

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
  --insecure    disable HTTPS check
  --no-cache    submit file even if a result already exists
  --help        Show this message and exit.

Commands:
  send*    send file to API.
  get      get result for given uuid.
  waitfor  send a file and wait for the result.
  search   get result for given sha256.
"""

from dataclasses import dataclass
import logging
import os
from typing import List

import click
import rich
from click_default_group import DefaultGroup
from rich.console import Console

from . import exceptions, log
from .api import Client
from .exceptions import GDetectError, NoAuthenticateToken, BadAuthenticationToken

# initialize rich Console for pretty print
console = Console()
error_console = Console(stderr=True, style="bold red")


@dataclass
class GDetectContext:
    """
    GDetect CLI context
    """

    logger: logging.Logger = log.get_logger()
    url: str = ''  # os.getenv("API_URL")
    token: str = ''  # os.getenv("API_TOKEN")
    insecure: bool = False
    no_cache: bool = False
    client: Client = None

    def __init__(self):
        self.url = os.getenv("API_URL")
        self.token = os.getenv("API_TOKEN")


@click.group(cls=DefaultGroup, default="send", default_if_no_args=True)
@click.option("--url", default="", help="url to GLIMPS Detect API")
@click.option("--token", default="", help="authentication token")
@click.option("--insecure", is_flag=True, help="bypass HTTPS check")
@click.option(
    "--no-cache",
    "nocache",
    is_flag=True,
    help="submit file even if a result already exists",
)
@click.option("--debug", is_flag=True, help="print debug strings")
@click.pass_context
def gdetect(
    ctx: click.Context = None,
    url: str = "",
    token: str = "",
    insecure: bool = False,
    nocache: bool = False,
    debug: bool = False
):
    """CLI for GLIMPS detect"""
    try:
        ctx.ensure_object(GDetectContext)
    except Exception as exc:
        print(exc)

    obj: GDetectContext = ctx.obj

    if debug is True:
        obj.logger.setLevel(logging.DEBUG)

    if token != "":
        obj.token = token
    if url != "":
        obj.url = url

    try:
        obj.client = Client(url=obj.url, token=obj.token)
    except GDetectError as exc:
        return handleGDetectError(exc)

    if insecure:
        error_console.print("untrusted: SSL verification disabled")
        obj.insecure = insecure
        obj.client.verify = not insecure
    if nocache:
        obj.no_cache = nocache
    # ctx.obj = obj


@gdetect.command("send")
@click.pass_obj
@click.argument("filename")
@click.option("-t", "--tag", multiple=True, help="tags to assign to the file.")
@click.option("-d", "--description", help="description of the file.")
def send(
    obj: GDetectContext = None,
    filename: str = "",
    tag: str = "",
    description: str = "",
):
    """send file to API."""
    try:
        uuid = obj.client.push(
            filename,
            bypass_cache=obj.no_cache,
            tags=tag,
            description=description,
        )
        console.print(uuid)

    except GDetectError as exc:
        handleGDetectError(exc)
        # print_response_error_msg(ctx.obj["client"].response.message)


@gdetect.command("get")
@click.pass_obj
@click.argument("uuid")
@click.option("--retrieve-urls", is_flag=True, default=False, help="retrieve urls")
def get(obj: GDetectContext = None, uuid: str = "", retrieve_urls: bool = False):
    """get result for given uuid."""
    try:
        result = obj.client.get_by_uuid(uuid)
        rich.print_json(data=result)
        if retrieve_urls:
            print_urls()

    except GDetectError as exc:
        handleGDetectError(exc)


@gdetect.command("search")
@click.argument("sha256")
@click.option("--retrieve-urls", is_flag=True, help="retrieve urls")
@click.pass_obj
def search(obj: GDetectContext = None, sha256: str = "", retrieve_urls: bool = False):
    """search a file with given sha256."""
    try:
        result = obj.client.get_by_sha256(sha256)
        rich.print_json(data=result)
        if retrieve_urls:
            print_urls()
    except GDetectError as exc:
        handleGDetectError(exc)


@gdetect.command("waitfor")
@click.pass_obj
@click.argument("filename")
@click.option("--timeout", default=180, help="set a timeout in seconds")
@click.option("-t", "--tag", multiple=True, help="tags to assign to the file.")
@click.option("-d", "--description", help="description of the file.")
@click.option("--retrieve-urls", is_flag=True, help="retrieve urls")
def waitfor(
    obj: GDetectContext = None,
    filename: str = "",
    timeout: int = 180,
    tag: List[str] = [],
    description: str = "",
    retrieve_urls: bool = False,
):
    """send a file and wait for the result."""
    try:
        result = obj.client.waitfor(
            filename,
            bypass_cache=obj.no_cache,
            timeout=timeout,
            tags=tag,
            description=description,
        )
        rich.print_json(data=result)
        if retrieve_urls:
            print_urls()
    except GDetectError as exc:
        handleGDetectError(exc)


def print_response_error_msg(msg):
    """print error messages inside console"""
    error_console.print(f"An error occurs: {msg}")


@click.pass_obj
def print_urls(obj: GDetectContext = None):
    """Print url for token and analyse view"""
    try:
        url_token_view = obj.client.extract_url_token_view()
        console.print("TOKEN VIEW URL: ", url_token_view)
    except (exceptions.MissingToken, exceptions.MissingResponse):
        pass

    try:
        url_expert_analyse = obj.client.extract_expert_url()
        console.print("ANALYSE VIEW URL: ", url_expert_analyse)
    except (exceptions.MissingSID, exceptions.MissingResponse):
        pass


def handleGDetectError(exc: GDetectError):

    if isinstance(exc, NoAuthenticateToken):
        error_console.print("Error: Missing argument 'TOKEN'")
    elif isinstance(exc, BadAuthenticationToken):
        error_console.print("Error: Invalid 'TOKEN'")
    else:
        error_console.print("error: %r" % exc)


if __name__ == "__main__":
    gdetect()
