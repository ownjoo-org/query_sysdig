import logging
import sys
from typing import Generator, Optional

from ownjoo_utils.logging.consts import LOG_FORMAT
from ownjoo_utils.logging.decorators import timed_generator
from ownjoo_utils.parsing.consts import TimeFormats
from ownjoo_utils.parsing.types import get_value
from query_sysdig.consts import (
    BACK_OFF, BASE_URL, CVE_ID_PATTERN, DELAY, LOG_PROGRESS, LOG_PROGRESS_INTERVAL,
    MAX_DELAY, PAGE_SIZE, RETRY_COUNT, RETRY_ON, UUID_PATTERN, UUID_REX,
)
from requests import Response, Session
from requests.exceptions import HTTPError
from retry import retry
from urllib3 import Retry

logging.basicConfig(
    format=LOG_FORMAT,
    level=logging.INFO,
    datefmt=TimeFormats.date_and_time.value,
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

session: Optional[Session] = None


@retry(exceptions=RETRY_ON, tries=RETRY_COUNT, delay=DELAY, backoff=BACK_OFF, max_delay=MAX_DELAY, logger=logger)
def get_response(
        url: str,
        method: str = 'GET',
        params=None,
        json: Optional[dict] = None,
        data: Optional[dict] = None,
) -> Optional[dict]:
    """Fetch URL with retries on failure, including exponential backoff."""
    try:
        r: Response = session.request(method=method, url=url, data=data, json=json, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as exc_http:
        if isinstance(exc_http, HTTPError):
            logger.exception(
                f'HTTP Error: {exc_http}:\n'
                f'{exc_http.response.status_code=}\n'
                f'{exc_http.request.url=}\n'
            )
        raise


# @timed_generator(log_progress=False, logger=logger)
def list_results_paginated(domain: str, additional_params: Optional[dict] = None) -> Generator[dict, None, None]:
    """Fetch paginated runtime vulnerability results from the Sysdig API."""
    params: dict = {'limit': PAGE_SIZE}
    if isinstance(additional_params, dict):
        params.update(additional_params)

    should_continue: bool = True
    while should_continue:
        data: dict = get_response(url=domain, params=params)
        yield from get_value(src=data, path=['data'], exp=list, default=[])
        params['cursor'] = get_value(src=data, path=['page', 'next'], exp=str)
        should_continue = bool(get_value(src=params, path=['cursor'], exp=str))


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def list_runtime_results(domain: str = BASE_URL) -> Generator[dict, None, None]:
    """Fetch paginated runtime vulnerability results from the Sysdig API."""
    yield from list_results_paginated(
        domain=f'{domain}/api/scanning/runtime/v2/workflows/results',
        additional_params={
            'filter': 'asset.type="container"',
            'order': 'desc',
            'sort': 'runningVulnsBySev'
        },
    )


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def list_host_results(domain: str = BASE_URL) -> Generator[dict, None, None]:
    """Fetch paginated host results from the Sysdig API."""
    yield from list_results_paginated(
        domain=f'{domain}/api/scanning/runtime/v2/workflows/results',
        additional_params={
            'filter': 'asset.type="host"',
            'order': 'desc',
            'sort': 'runningVulnsBySev',
        },
    )


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def fetch_result_details(domain: str = BASE_URL, result_id: str = '') -> Generator[dict, None, None]:
    """Fetch detailed information for a specific result ID."""
    yield get_response(
        url=f'{domain}/secure/vulnerability/v1/results/{result_id}',
    )


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def list_parsed_cves(data: dict, result_id, container_name, environment, zone) -> Generator[dict, None, None]:
    """Parse the vulnerability data and extract the relevant information."""

    base_name: str = container_name.rsplit('_', 1)[0]
    try:
        base_name = UUID_PATTERN.match(container_name).group(1)
    except Exception as exc_rex:
        logger.debug(f'ERROR matching {container_name=}: {exc_rex=} ({UUID_REX=})')

    result: dict = get_value(src=data, path=['result'], exp=dict, default={})
    asset_type: str = get_value(src=data, path=['result', 'type'], exp=str, default='unknown')

    host_or_container: Optional[str] = None
    if asset_type == 'host':
        host_or_container: str = get_value(src=result, path=['metadata', 'hostName'])
    elif asset_type == 'container':
        host_or_container: str = get_value(src=result, path=['metadata', 'pullString'])

    for package in get_value(src=result, path=['packages'], exp=list, default=[]):
        package_name = get_value(src=package, path=['name'], exp=str, default='unknown')
        for vuln in get_value(src=package, path=['vulns'], exp=list, default=[]):
            if cve_id := get_value(
                    src=vuln,
                    path=['name'],
                    exp=str,
                    validator=lambda v: isinstance(v, str) and bool(CVE_ID_PATTERN.findall(v)),
            ):
                risk_accepted: bool = get_value(src=vuln, path=['acceptedRisks'], exp=bool, converter=lambda v: bool(v))
                severity: str = get_value(src=vuln, path=['severity', 'value'], exp=str, default='unknown')
                yield {
                    'cveId': cve_id,
                    'assetType': asset_type,
                    'hostOrContainer': host_or_container,
                    'packageName': package_name,
                    'severity': severity,
                    'resultId': result_id,
                    'riskAcceptance': risk_accepted,
                    'containerName': container_name,
                    'deploymentName': base_name,
                    'environment': environment,
                    'zone': zone,
                }


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def list_enriched_details(data: dict, result_id, container_name, environment, zone) -> Generator[dict, None, None]:
    """Parse the vulnerability data and extract the relevant information."""

    base_name: str = container_name.rsplit('_', 1)[0]
    result: dict = get_value(src=data, path=['result'], exp=dict, default={})
    asset_type: str = get_value(src=data, path=['result', 'type'], exp=str)
    if not asset_type:
        asset_type: str = get_value(src=data, path=['result', 'assetType'], exp=str)

    host_or_container: Optional[str] = None
    match asset_type:
        case 'host':
            host_or_container = get_value(src=result, path=['metadata', 'hostName'], exp=str, default='unknown')
        case 'container':
            host_or_container = get_value(src=result, path=['metadata', 'pullString'], exp=str, default='unknown')
        case 'containerImage':
            host_or_container = get_value(src=result, path=['metadata', 'pullString'], exp=str, default='unknown')
        case _:
            host_or_container = 'unknown'

    result['deploymentName'] = base_name
    result['environment'] = environment
    result['name'] = host_or_container
    result['resultId'] = result_id
    result['zone'] = zone
    yield result


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def process_result(domain, result_id, container_name, environment, zone) -> Generator[dict, None, None]:
    """Process a single result and return parsed CVE data."""
    try:
        # yield from fetch_result_details(url=url, result_id=result_id)
        for result in fetch_result_details(domain=domain, result_id=result_id):
            # yield from list_parsed_cves(result, result_id, container_name, environment, zone)
            yield from list_enriched_details(result, result_id, container_name, environment, zone)
    except Exception as e:
        logging.error(f"Error processing result ID {result_id}: {e}")


@timed_generator(log_progress=LOG_PROGRESS, log_progress_interval=LOG_PROGRESS_INTERVAL, logger=logger)
def list_results(domain: str) -> Generator[dict, None, None]:
    """Main function to fetch, process, and save vulnerability data."""

    # Create a map of all host info first
    host_info: dict = {}

    # collect all host information
    for record in list_host_results(domain=domain):
        if host_name := get_value(src=record, path=['recordDetails', 'labels', 'host.hostName'], exp=str):
            host_info[host_name]: dict = {
                'environment': get_value(
                    src=record,
                    path=['recordDetails', 'labels', 'agent.tag.environment'],
                    exp=str,
                ),
                'zone': get_value(
                    src=record,
                    path=['recordDetails', 'labels', 'agent.tag.zone'],
                    exp=str,
                ),
            }

    # yield containers with environment, zone and CVEs
    for record in list_runtime_results(domain=domain):
        host_name: str = get_value(src=record, path=['recordDetails', 'labels', 'host.hostName'], exp=str)
        container_name: str = get_value(src=record, path=['recordDetails', 'labels', 'container.name'], exp=str)

        if not container_name and host_name:
            continue

        yield from process_result(
            domain=domain,
            result_id=get_value(src=record, path=['resultId'], exp=str),
            container_name=container_name,
            environment=get_value(src=host_info, path=[host_name, 'environment'], exp=str, default='unknown'),
            zone=get_value(src=host_info, path=[host_name, 'zone'], exp=str, default='unknown'),
        )

def main(domain: str, api_key: str, proxies: Optional[dict] = None) -> Generator[dict, None, None]:
    global session
    session = Session()
    session.proxies.update(proxies or {})
    session.headers.update(
        {
            'Accept': 'application/json',
            'Authorization': f'Bearer {api_key}',
        }
    )
    for adapter in session.adapters.values():
        adapter.max_retries = Retry(
            total=RETRY_COUNT,
            backoff_factor=BACK_OFF,
            status_forcelist=[502, 503, 504],
        )

    return list_results(domain=domain)
