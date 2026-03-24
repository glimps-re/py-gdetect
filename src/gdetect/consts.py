"""
gdetect constants
"""

import re

GDETECT_USER_AGENT = "py-gdetect/0.8.0"
BASE_ENDPOINT = "/api/lite/v2"
EXPORT_FORMATS = ["misp", "stix", "json", "pdf", "markdown", "csv"]
EXPORT_LAYOUTS = ["en", "fr"]
WAIT_MIN_VALUE = 0
WAIT_MAX_VALUE = 59
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
TOKEN_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}")
