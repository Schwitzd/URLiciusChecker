import argparse
from URLiciusChecker.SuspiciousURLChecker import SuspiciousURLChecker

print('''
 _   _______ _     _      _                   _____ _               _             
| | | | ___ \ |   (_)    (_)                 /  __ \ |             | |            
| | | | |_/ / |    _  ___ _  ___  _   _ ___  | /  \/ |__   ___  ___| | _____ _ __ 
| | | |    /| |   | |/ __| |/ _ \| | | / __| | |   | '_ \ / _ \/ __| |/ / _ \ '__|
| |_| | |\ \| |___| | (__| | (_) | |_| \__ \ | \__/\ | | |  __/ (__|   <  __/ |   
 \___/\_| \_\_____/_|\___|_|\___/ \__,_|___/  \____/_| |_|\___|\___|_|\_\___|_|   
                                                                            v0.1.0
''')


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Check if a URL is suspicious')
    parser.add_argument('--url', metavar='URL',
                        required=True, help='URL to check')
    return parser.parse_args()


def main() -> None:
    args = get_args()

    checker = SuspiciousURLChecker(args.url)
    url_domain, url_tld, evaluation = checker.is_suspicious_url()

    print('\033[1m' + f'URL:\033[0m {args.url}')
    print('\033[1m' + f'Domain:\033[0m {url_domain}')
    print('\033[1m' + f'TLD:\033[0m {url_tld}')
    print('\033[1m' + f'Evaluation:\033[0m {evaluation}')


if __name__ == '__main__':
    main()
