"""Api is a module to connect to GLIMPS detect service.

This module helps to use GLIMPS detect. Main parameters are the token and the url.
If no token is given to constructor, the Api class tries to get the 'API_TOKEN' environment variable.
If this variable doesn't exist, a exception is raised.

The behavior is similar for url: tries to get environment variable 'API_URL' or raises exception.

Usage examples:

>>> client = Client(API_URL, API_TOKEN)
>>> client.push('malware.elf')
9d488d01-23d5-4b9f-894e-c920ea732603
>>> client.get('9d488d01-23d5-4b9f-894e-c920ea732603')
{
    'uuid': '9d488d01-23d5-4b9f-894e-c920ea732603',
    'sha256': '7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99',
    'sha1': 'e0b77bdd78bf3215221298475c88fb23e4e84f98',
    'md5': 'e1c080be1a748d69246ad9c766ad8809',
    'ssdeep': '384:MCDKKQOcRpmYLdn6RBOFRFt5rUFX1DiSIlCo3AnupCFNqnrrd1NEZgO8UXWozPLL:
P/QOC0Yhn6ROHWFlAcwNEFCnNBxc6nc/',
    'is_malware': True,
    'score': 3000,
    'done': True,
    'timestamp': 0,
    'filetype': 'elf',
    'size': 24728,
    'filenames': ['sha256'],
    'files': [
        {...
        }
    ], 'sid': '7UZy0tbWPSTdNfkzKSW5gS', ...
}
"""

from dataclasses import asdict, dataclass
import pathlib
import time
import urllib.parse
import re

import requests
import urllib3


from requests.exceptions import JSONDecodeError


from .log import get_logger
from .exceptions import (
    BadAuthenticationTokenError,
    BadSHA256Error,
    BadUUIDError,
    GDetectError,
    GDetectTimeoutError,
    InternalServerError,
    MissingSIDError,
    MissingTokenError,
    NoAuthenticationTokenError,
    ResultNotFoundError,
    TooManyRequestsError,
    UnauthorizedAccessError,
)
from .stream import StreamReader

logger = get_logger()

BASE_ENDPOINT = "/api/lite/v2"

UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
TOKEN_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}"
)
GDETECT_USER_AGENT = "py-gdetect/0.6.0"


@dataclass
class Status:
    """Detect profile status
    daily_quota (int): Number of submissions authorized for the profile within 24h.
    available_daily_quota (int): Number of submissions still available within 24h.
            It's a sliding window, so a new slot will be released 24h after each submission.
    cache (bool): If True, the profile is configured to use cached result by default.
    estimated_analysis_duration (int): It's an estimation of the duration for the next submissions in milliseconds.
            It's based on the average time of submissions and the submission queue state.
            The real duration could differ from the estimation.
    """

    daily_quota: int
    available_daily_quota: int
    cache: bool
    estimated_analysis_duration: int

    def to_dict(self) -> dict:
        return asdict(self)


class Client:
    """Client class builds an object to interact with url.

    The constructor takes 2 parameters: 'url' and 'token'.

    Attributes:
        url (str): URL of the API.
        token (str): The authentication token.
        verify (bool): If `False`, this bypass SSL checks. *Only for testing*.
                       **Not recommended in production !**
        response (Response): A Response dataclass with detailed return.
    """

    def __init__(self, url: str, token: str):
        self.base_url = url
        self.url = urllib.parse.urljoin(url, BASE_ENDPOINT)
        self.token: str = token
        self._verify: bool = True
        self.timeout: float = 30.0
        # check inputs
        self._check_token()

    @property
    def verify(self) -> bool:
        """Does the client need to check TLS certificates"""
        return self._verify

    @verify.setter
    def verify(self, enable_check: bool):
        if not enable_check:
            # remove print of requests warning about SSL
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._verify = enable_check

    def push_reader(
        self,
        filename: str,
        reader: StreamReader,
        bypass_cache: bool = False,
        tags: tuple = (),
        description: str = None,
        archive_password: str = None,
    ) -> str:
        """Push a file to API endpoint (using reader).

        Args:
            filename (str): name of submitted file.
            bypass_cache (bool, optional):
                If True, the file is analyzed, even if a result already exists.
            tags (tuple, optional): If filled, the file will be tagged with those tags.
            description (str, optional): If filled, a description will be added to the analysis.
            archive_password (str, optional) : If filled, the password used to extract archive.

        Returns:
            uuid (str): unique id of analysis

        Raises:
            GDetectError: GMalware server returned an error.
            OSError: there was an error with the input file.
            requests.RequestException: there was an error reaching GMalware server
        """

        # prepare request
        files = {"file": (filename, reader)}
        params = {
            "bypass-cache": f"{bool(bypass_cache)}",
            "tags": ",".join(tags),
            "description": description,
            "archive_password": archive_password,
        }
        path = f"{self.url}/submit"

        # send request
        resp = self._request(
            "post",
            path,
            params=params,
            files=files,
        )

        # parse response and return UUID
        try:
            response = resp.json()
        except JSONDecodeError as exc:
            raise GDetectError("invalid GLIMPS Detect response") from exc
        if not isinstance(response, dict):
            raise GDetectError("invalid GLIMPS Detect response")
        if "uuid" not in response:
            raise GDetectError("invalid GLIMPS Detect response")
        return response["uuid"]

    def push(
        self,
        filename: str,
        bypass_cache: bool = False,
        tags: tuple = (),
        description: str = None,
        archive_password: str = None,
    ) -> str:
        """Push a file to API endpoint.

        Args:
            filename (str): Fullpath of submitted file.
            bypass_cache (bool, optional):
                If True, the file is analyzed, even if a result already exists.
            tags (tuple, optional): If filled, the file will be tagged with those tags.
            description (str, optional): If filled, a description will be added to the analysis.
            archive_password (str, optional) : If filled, the password used to extract archive.

        Returns:
            uuid (str): unique id of analysis

        Raises:
            GDetectError: GMalware server returned an error.
            OSError: there was an error with the input file.
            requests.RequestException: there was an error reaching GMalware server
        """

        with open(filename, "rb") as reader:
            return self.push_reader(
                pathlib.Path(filename).name,
                reader,
                bypass_cache,
                tags,
                description,
                archive_password,
            )

    def get_by_sha256(self, sha256: str) -> dict:
        """Retrieve analysis result using file sha256

        Args:
            sha256 (str): sha256 of the file

        Raises:
            exceptions.GDetectError: An error occured.

        Returns:
            dict: The json-encoded content of a response, if any.
        """
        # check inputs
        self._check_sha256(sha256)

        # prepare request
        path = f"{self.url}/search/{sha256}"

        # send request
        response = self._request("get", path)

        return response.json()

    def get_by_uuid(self, uuid: str) -> dict:
        """Retrieve analysis result using analysis uuid

        Args:
            uuid (str): identification number of submitted file.

        Returns:
            result (dict): The json-encoded content of a response, if any.

        Raises:
            exceptions.GDetectError: An error occured.
        """

        # check inputs
        self._check_uuid(uuid)

        # prepare request
        path = f"{self.url}/results/{uuid}"

        # send request
        response = self._request("get", path)

        return response.json()

    def waitfor(
        self,
        filename: str,
        bypass_cache: bool = False,
        pull_time: float = 1.0,
        timeout: float = 180,
        tags: tuple = (),
        description: str = None,
        archive_password: str = None,
    ) -> object:
        """Send a file to GLIMPS Detect and wait for a result.

        This function is an 'all-in-one' for sending and getting result.
        The pull time is arbitrary set to 5 seconds, and timeout to 3 minutes.

        Args:
            filename (str): Fullpath of submitted file.
            bypass_cache (bool): If True, the file is analyzed, even if a result already exists.
            pull_time (float): The time to wait (in seconds) between each requests to get a result.
            timeout (float): The maximum time execution of this method in seconds.
            tags (tuple, optional): If filled, the file will be tagged with those tags.
            description (str, optional): If filled, a description will be added to the analysis.
            archive_password (str, optional) : If filled, the password used to extract archive

        Returns:
            result (object): The json-encoded content of a response, if any.

        Raises:
            exceptions.GDetectError: An error occurs.
        """
        with open(filename, "rb") as reader:
            return self.waitfor_reader(
                pathlib.Path(filename).name,
                reader,
                bypass_cache,
                pull_time,
                timeout,
                tags,
                description,
                archive_password,
            )

    def waitfor_reader(
        self,
        filename: str,
        reader: StreamReader,
        bypass_cache: bool = False,
        pull_time: float = 1,
        timeout: float = 180,
        tags: tuple = (),
        description: str = None,
        archive_password: str = None,
    ) -> object:
        """Send a file to GLIMPS Detect and wait for a result (using reader).

        This function is an 'all-in-one' for sending and getting result.
        The pull time is arbitrary set to 5 seconds, and timeout to 3 minutes.

        Args:
            filename (str): name of submitted file.
            reader (StreamReader): a reader for the binary
            bypass_cache (bool): If True, the file is analyzed, even if a result already exists.
            pull_time (float): The time to wait (in seconds) between each requests to get a result.
            timeout (float): The maximum time execution of this method in seconds.
            tags (tuple, optional): If filled, the file will be tagged with those tags.
            description (str, optional): If filled, a description will be added to the analysis.
            archive_password (str, optional) : If filled, the password used to extract archive

        Returns:
            result (object): The json-encoded content of a response, if any.

        Raises:
            exceptions.GDetectError: An error occurs.
        """
        start_time = time.time()
        # push file, get uuid
        uuid = self.push_reader(
            filename,
            reader,
            bypass_cache=bypass_cache,
            tags=tags,
            description=description,
            archive_password=archive_password,
        )

        # get result
        while True:
            result = self.get_by_uuid(uuid)
            if result["done"]:
                return result
            if time.time() - start_time > timeout:
                raise GDetectTimeoutError(f"analysis took more than {timeout}s")
            time.sleep(pull_time)

    def get_status(self) -> Status:
        """
        Get detect profile status
        """
        # prepare request
        path = f"{self.url}/status"

        # send request
        response = self._request("get", path)

        status = response.json()
        return Status(
            daily_quota=status.get("daily_quota", 0),
            available_daily_quota=status.get("available_daily_quota", 0),
            cache=status.get("cache", False),
            estimated_analysis_duration=status.get("estimated_analysis_duration", 0),
        )

    def extract_url_token_view(self, resp: dict) -> str:
        """Extract url token view from response.

        Raises:
            exceptions.MissingToken: In case there is no token or no response at all.
            exceptions.MissingResponse: In case there is no response at all.

        Returns:
            str: token view url
        """
        token = resp.get("token", "")
        if token == "":
            raise MissingTokenError()
        return urllib.parse.urljoin(
            self.base_url, f"/expert/en/analysis-redirect/{token}"
        )

    def extract_expert_url(self, resp: dict) -> str:
        """Extract expert view from response.

        Raises:
            exceptions.MissingToken: In case there is no token in the response.
            exceptions.MissingResponse: In case there is no response at all.

        Returns:
            str: expert analysis view url
        """
        sid = resp.get("sid", "")
        if sid == "":
            raise MissingSIDError()
        return urllib.parse.urljoin(
            self.base_url, f"/expert/en/analysis/advanced/{sid}"
        )

    def _check_uuid(self, uuid: str):
        if not UUID_PATTERN.match(uuid):
            raise BadUUIDError

    def _check_sha256(self, sha256):
        if not SHA256_PATTERN.match(sha256):
            raise BadSHA256Error

    def _check_token(self):
        if self.token is None or self.token == "":
            raise NoAuthenticationTokenError()
        if not isinstance(self.token, str):
            raise BadAuthenticationTokenError("token must a be string")
        if not TOKEN_PATTERN.match(self.token):
            raise BadAuthenticationTokenError("bad token format")

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Process a request to URL with given method and params.

        This function execute the request to the URL with `requests` library.
        The return is wrapped inside a Response dataclass to simplify exceptions
        handling and logging.

        Args:
            method (str): request type (GET, POST,...).
            url (str): URL to join.
            **kwargs (str): named options of requests library.

        Returns:
            Response: a :class:`~Response` object.
        """
        # get request timeout
        timeout = kwargs.pop("timeout", self.timeout)
        headers = kwargs.pop("headers", {})
        # set auth token if not provided
        headers["X-Auth-Token"] = headers.get("X-Auth-Token", self.token)
        headers["User-Agent"] = GDETECT_USER_AGENT
        resp = requests.request(
            method, url, timeout=timeout, verify=self.verify, headers=headers, **kwargs
        )
        code = resp.status_code
        if code != 200:
            raise compute_exception_from_response(resp)
        return resp


HTTPExceptions = {
    401: UnauthorizedAccessError,
    403: UnauthorizedAccessError,
    404: ResultNotFoundError,
    429: TooManyRequestsError,
    500: InternalServerError,
}


def compute_exception_from_response(resp: requests.Response) -> GDetectError:
    """Compute a GDetectError from an requests.Response"""
    exc = HTTPExceptions.get(resp.status_code, GDetectError)
    try:
        msg = resp.json()
        return exc(msg.get("error", ""))
    except JSONDecodeError:
        return exc
