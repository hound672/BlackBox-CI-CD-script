import re
from typing import Optional

from blackbox_ci.consts import DEFAULT_SCHEME, STANDARD_PORT_SCHEMES
from blackbox_ci.errors import UrlParseError
from blackbox_ci.types import UrlParts

URL_PATTERN = re.compile(
    r"""^
            (?: (?P<scheme> https? ) :// )?
            (?P<hostname> [^\s@.:/?&#]+ (?: \. [^\s@.:/?&#]+ )* )
            (?: : (?P<port> \d{1,5} ) )?
            (?P<path> (?:/ [^\s/?#]*)+ )?
            (?: \? (?P<query> [^\s#]* ) )?
            (?: \# (?P<fragment> [^\s]* ) )?
        $""",
    re.IGNORECASE | re.VERBOSE,
)
"""
    Url pattern (scheme://)hostname(:port)(path)(?query)(#fragment)
    where parts in round brackets are optional. E.g.:
    https://example.com:443/path/to/resource?a=1&b=2&c=abc#end
    scheme='https'; hostname='example.com'; port=443; path='/path/to/resource';
    query='a=1&b=2&c=abc'; fragment='end'.
    Scheme, hostname, port, path, query and fragment are captured by capturing groups
"""


def parse_url(url: str, drop_fragment: bool = False) -> UrlParts:
    match = URL_PATTERN.match(url)
    if not match:
        raise UrlParseError(f'Could not parse URL: {url}')

    parts = UrlParts(
        **{x: match.group(x) for x in UrlParts._fields if x != 'port'},
        port=int(match.group('port')) if match.group('port') else None,
    )

    scheme = _normalize_scheme(parts.scheme, parts.port)
    if scheme is None:
        raise UrlParseError(f'Could not guess scheme for URL: {url}')

    hostname = _normalize_hostname(parts.hostname)
    port = _normalize_port(parts.scheme, parts.port)
    path = _normalize_path(parts.path)
    query = _normalize_query(parts.query)
    fragment = _normalize_fragment(parts.fragment, drop_fragment)
    return UrlParts(scheme, hostname, port, path, query, fragment)


def unparse_url(parts: UrlParts) -> str:  # noqa: C901
    url = parts.hostname
    if parts.scheme is not None:
        url = parts.scheme + '://' + url
    if parts.port is not None:
        url = url + ':' + str(parts.port)
    if parts.path is not None:
        url += parts.path
    if parts.query is not None:
        url += '?' + parts.query
    if parts.fragment is not None:
        url += '#' + parts.fragment
    return url


def normalize_url(url: str, drop_fragment: bool = False) -> str:
    return unparse_url(parse_url(url, drop_fragment))


def _normalize_scheme(scheme: Optional[str], port: Optional[int]) -> Optional[str]:
    if scheme is None:
        if port is None:
            return DEFAULT_SCHEME
        elif port in STANDARD_PORT_SCHEMES:
            return STANDARD_PORT_SCHEMES[port]
        else:
            return None
    return scheme.lower()


def _normalize_hostname(hostname: str) -> str:
    return hostname.lower()


def _normalize_port(scheme: str, port: Optional[int]) -> Optional[int]:
    if scheme == 'http':
        if port == 80:
            return None
    elif scheme == 'https':
        if port == 443:
            return None
    return port


def _normalize_path(path: Optional[str]) -> str:
    return path or '/'


def _normalize_query(query: Optional[str]) -> Optional[str]:
    return query or None


def _normalize_fragment(fragment: Optional[str], drop_fragment: bool) -> Optional[str]:
    if drop_fragment:
        return None
    return fragment or None
