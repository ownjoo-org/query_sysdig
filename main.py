import argparse
import json
from typing import Optional

from template_cli.main import main


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
        '--domain',
        default='example.com',
        type=str,
        required=False,
        help='The FQDN for your API (not full URL)',
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

    result = main(
        domain=args.domain,
        api_key=args.client_id,
        proxies=proxies,
    )

    if result:
        print(json.dumps(result, indent=4))
    else:
        print('No results found')
