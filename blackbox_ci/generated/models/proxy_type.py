from enum import Enum


class ProxyType(str, Enum):
    HTTP = 'http'
    HTTPS = 'https'
    HTTP_NO_CONNECT = 'http_no_connect'
    SOCKS4 = 'socks4'
    SOCKS5 = 'socks5'
    SOCKS5H = 'socks5h'
    TRANSPARENT = 'transparent'

    def __str__(self) -> str:
        return str(self.value)
