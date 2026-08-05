from enum import Enum


class TemplateName(str, Enum):
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    PLAIN = 'plain'
    SANS = 'sans'

    def __str__(self) -> str:
        return str(self.value)
