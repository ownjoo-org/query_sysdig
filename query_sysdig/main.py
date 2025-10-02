import logging
from json import loads
from typing import Generator, Optional

from ownjoo_utils import get_value
from query_sysdig.client import fetch_data
from query_sysdig.models import Container, Host, Result

logger = logging.getLogger(__name__)


def main(base_url: str, api_key: str, proxies: Optional[dict] = None) -> Generator[dict, None, None]:
    # init DBs
    Container.create_table()
    Host.create_table()
    Result.create_table()

    # retrieve data and save to DBs
    fetch_data(base_url=base_url, api_key=api_key, proxies=proxies)

    # query data from local DBs
    # TODO: add join relations
    # TODO: add view classes to easily switch out result formats
    for result in Result.select().dicts():
        result['data'] = loads(get_value(src=result, path=['data'], exp=str, default='{}'))
        yield result
    for host in Host.select().dicts():
        host['data'] = loads(get_value(src=host, path=['data'], exp=str, default='{}'))
        yield host
    for container in Container.select().dicts():
        container['data'] = loads(get_value(src=container, path=['data'], exp=str, default='{}'))
        yield container
