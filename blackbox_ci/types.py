import sys
import typing
from enum import Enum

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict

VulnCommon = typing.Dict[str, typing.Any]


ScanStatus = Literal[
    'CREATED', 'SENT_START_TASK', 'STARTED', 'SENT_STOP_TASK', 'STOPPED', 'FINISHED'
]


class VulnGroup(TypedDict):
    issueType: str
    categoryLocaleKey: str
    count: int
    # reflects group name on UI
    groupTitle: str
    requestKey: typing.Optional[str]
    severity: str
    vulnerability: VulnCommon


class VulnPage(TypedDict):
    totalItems: int
    hasPrevPage: bool
    hasNextPage: bool
    pagesCount: int
    currentPage: int
    items: typing.List[VulnCommon]


class VulnIssue(TypedDict):
    """Vuln type: issue"""

    url: str


class VulnErrorPage(TypedDict):
    """Vuln type: error_page"""

    url: str


class VulnCve(TypedDict):
    """Vuln type: cve"""

    cve_id: str
    vector: str


class GroupIssue(TypedDict):
    severity: str
    category: str
    group_title: str
    vulns: typing.List[VulnIssue]


class GroupErrorPage(TypedDict):
    group_title: str
    category: str
    vulns: typing.List[VulnErrorPage]


class GroupCve(TypedDict):
    category: str
    group_title: str
    vulns: typing.List[VulnCve]


class TargetVulns(TypedDict):
    issue_groups: typing.List[GroupIssue]
    cve_groups: typing.List[GroupCve]
    error_page_groups: typing.List[GroupErrorPage]


class ScanReport(TypedDict):
    target_url: str
    url: str
    vulns: typing.Optional[TargetVulns]
    sharedLink: typing.Optional[str]
    score: typing.Optional[float]
    report_path: typing.Optional[str]


class ScanProfile(TypedDict):
    uuid: str
    name: str
    type: str


class AuthenticationProfile(TypedDict):
    uuid: str
    name: str
    type: str


class APIProfile(TypedDict):
    uuid: str
    name: str
    countOfSchemas: int


class SiteSettings(TypedDict):
    url: str
    name: str
    profile: ScanProfile
    authentication: typing.Optional[AuthenticationProfile]
    apiProfile: typing.Optional[APIProfile]


class Scan(TypedDict):
    errorReason: typing.Optional[str]
    id: int
    status: ScanStatus
    progress: int
    profile: ScanProfile
    authentication: typing.Optional[AuthenticationProfile]
    apiProfile: typing.Optional[APIProfile]
    score: float


class SiteGroupInfo(TypedDict):
    uuid: str
    name: str


class Site(TypedDict):
    uuid: str
    url: str
    name: str
    lastScan: typing.Optional[Scan]
    profile: ScanProfile
    authentication: typing.Optional[AuthenticationProfile]
    apiProfile: typing.Optional[APIProfile]
    group: SiteGroupInfo


class UserGroupInfo(SiteGroupInfo):
    type: str
    role: str


class UrlParts(typing.NamedTuple):
    scheme: str
    hostname: str
    port: typing.Optional[int]
    path: typing.Optional[str]
    query: typing.Optional[str]
    fragment: typing.Optional[str]


class ReportTemplateShortname(str, Enum):
    HTML = 'html'
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    SARIF = 'sarif'
    SANS = 'sans'


class ReportExtension(str, Enum):
    HTML = 'html'
    SARIF = 'sarif'


class ReportLocale(str, Enum):
    RU = 'ru'
    EN = 'en'


class ReportHTMLTemplate(str, Enum):
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    PLAIN = 'plain'
    SANS = 'sans'
