import argparse
import json
import logging
from sys import stderr
from typing import Optional

from ownjoo_utils.logging.consts import LOG_FORMAT
from ownjoo_utils.parsing.consts import TimeFormats

from query_sysdig.main import main


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--api-key',
        default=None,
        type=str,
        required=True,
        help='The API key',
        dest='api_key',
    )
    parser.add_argument(
        '--base-url',
        default='http://example.com:8080',
        type=str,
        required=False,
        help='The base URL for you sysdig (or test) endpoint',
        dest='base_url',
    )
    parser.add_argument(
        '--proxies',
        type=str,
        required=False,
        help="JSON structure specifying 'http' and 'https' proxy URLs",
    )
    parser.add_argument(
        '--log-level',
        type=int,
        required=False,
        help="log level (0-60)",
        default=logging.INFO,
        dest='log_level',
    )

    args = parser.parse_args()

    logging.basicConfig(
        format=LOG_FORMAT,
        level=args.log_level,
        datefmt=TimeFormats.date_and_time.value,
        stream=stderr,
    )

    proxies: Optional[dict] = None
    if proxies:
        try:
            proxies: dict = json.loads(args.proxies)
        except Exception as exc_json:
            print(
                f'WARNING: failure parsing proxies: {exc_json}: proxies provided: {proxies}'
            )

    print('[')
    for result in main(base_url=args.base_url, api_key=args.api_key, proxies=proxies):
        if result:
            print(f'{json.dumps(result)},')
    print(']')
