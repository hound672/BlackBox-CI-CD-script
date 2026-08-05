from enum import Enum


class AuthenticationType(str, Enum):
    API_KEY = 'API_KEY'
    BEARER = 'BEARER'
    HTML_AUTO_FORM = 'HTML_AUTO_FORM'
    HTML_FORM_BASED = 'HTML_FORM_BASED'
    HTTP_BASIC = 'HTTP_BASIC'
    RAW_COOKIE = 'RAW_COOKIE'

    def __str__(self) -> str:
        return str(self.value)
