import logging
from time import sleep
from typing import Generator, Optional, Union

from ownjoo_utils.logging.consts import LOG_FORMAT, TIME_FORMAT
from ownjoo_utils.logging.decorators import timed_generator
from requests import Response, Session

logging.basicConfig(
    format=LOG_FORMAT,
    level=logging.INFO,
    datefmt=TIME_FORMAT,
)
logger = logging.getLogger(__name__)

S: Session = Session()


@timed_generator(log_progress=False, log_level=logging.DEBUG, logger=logger)
def list_results(
    url: str, additional_params: Optional[dict] = None
) -> Generator[dict, None, None]:
    should_continue: bool = True
    params: dict = {
        'offset': 0,
        'limit': 1000,
    }
    if isinstance(additional_params, dict):
        params.update(additional_params)
    expected_total: int = 0
    count: int = 0
    retries: int = 3
    while should_continue and retries > 0:
        try:
            r: Response = S.get(url, params=params)
            r.raise_for_status()
            data_raw: dict = r.json()
            results: list = data_raw.get('results')
            if not expected_total:
                expected_total = data_raw.get('count') or 0
                # logger.info(f'Expected count of {expected_total} for {url}')
            if not results:
                should_continue = False
            count += len(results)
            params['offset'] += 1000
            yield from results
            retries = 3
        except Exception as e:
            logger.error(f'ERROR {url}: {str(e)[:200]}.  Retries: {retries}')
            retries -= 1
            sleep(5)


def main(
    domain: str,
    api_key: str,
    proxies: Optional[dict] = None,
) -> Union[None, str, list, dict]:
    session = Session()

    if isinstance(proxies, dict):
        session.proxies = proxies

    headers: dict = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}',
    }
    S.headers.update(headers)

    return list(list_results(url=domain))
