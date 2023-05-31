from urllib.parse import urlparse
from typing import Tuple

class SuspiciousURLChecker:
    def __init__(self, input_url: str):
        self.input_url = input_url

    def is_suspicious_url(self) -> Tuple[str, str, str]:
        if '@' in self.input_url:
            self.input_url = self.input_url.split('://', 1)[-1]
            has_slash = '/' in self.input_url[:self.input_url.rfind('@')]
            has_fraction_slash = '\u2044' in self.input_url
            has_division_slash = '\u2215' in self.input_url

            if has_slash:
                domain = self.input_url.split('/')[0]
                note = "This URL is suspicious due to the presence of '@', which may indicate an error or obfuscation"

            if not has_slash and (has_fraction_slash or has_division_slash):
                domain = self.input_url.split('@')[-1].split('/')[0]
                note = 'This URL is potentially malicious due to the irregular use of characters and deviations from standard URL formats.'

            if not has_slash and (not has_fraction_slash or not has_division_slash):
                domain = self.input_url.split('@')[-1].split('/')[0]
                note = "This URL is suspicious due to the presence of '@', which may indicate an error or obfuscation"

        else:
            parsed_url = urlparse(self.input_url)
            domain = parsed_url.netloc
            note = 'This URL is not suspicious'

        tld = self.__suspicious_tld(domain)

        return domain, tld, note

    def __suspicious_tld(self, domain: str)-> str:
        tld = domain.split('.')[-1]
        if 'zip' in tld:
            return "'.zip' domain are mainly associated with phishing activities"

        return tld
