import re

import requests

BASE_URL = "https://api.sysdig.com"

# pagination
BACK_OFF: int = 2
DELAY: int = 1
MAX_DELAY: int = 30
PAGE_SIZE: int = 1000
REQ_TIMEOUT: float = 30.0
RETRY_COUNT: int = 3
RETRY_ON: tuple = (
    requests.ConnectionError,
    requests.RequestException,
    requests.Timeout,
)

# logging
LOG_PROGRESS: bool = True
LOG_PROGRESS_INTERVAL: int = 100


UUID_REX: str = r'(.*)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
UUID_PATTERN = re.compile(UUID_REX)

CVE_ID_REX: str = r'^CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,})$'
CVE_ID_PATTERN: re.Pattern = re.compile(CVE_ID_REX)
