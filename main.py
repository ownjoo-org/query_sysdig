import argparse
import json
from typing import Optional

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

    args = parser.parse_args()

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
