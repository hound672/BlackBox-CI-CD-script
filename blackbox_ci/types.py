from collections.abc import Callable
from enum import StrEnum
from typing import Any, NamedTuple, TypedDict, TypeVar

OnEnvUpdater = Callable[[dict[str, str]], None]


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
    vulns: list[VulnIssue]


class GroupErrorPage(TypedDict):
    group_title: str
    category: str
    vulns: list[VulnErrorPage]


class GroupCve(TypedDict):
    category: str
    group_title: str
    vulns: list[VulnCve]


class TargetVulns(TypedDict):
    issue_groups: list[GroupIssue]
    cve_groups: list[GroupCve]
    error_page_groups: list[GroupErrorPage]


class ReportScanStatus(StrEnum):
    in_progress = 'in_progress'
    stopped = 'stopped'
    finished = 'finished'


class ErrorReport(TypedDict):
    short_info: str
    message: str
    json: dict[Any, Any] | None


class ScanReport(TypedDict):
    target_url: str | None
    target_uuid: str | None
    url: str | None
    scan_status: ReportScanStatus | None
    vulns: TargetVulns | None
    sharedLink: str | None
    score: float | None
    report_path: str | None
    errors: list[ErrorReport] | None


class UrlParts(NamedTuple):
    scheme: str
    hostname: str
    port: int | None
    path: str | None
    query: str | None
    fragment: str | None


class ReportTemplateShortname(StrEnum):
    HTML = 'html'
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    SARIF = 'sarif'
    SANS = 'sans'


class ReportExtension(StrEnum):
    HTML = 'html'
    SARIF = 'sarif'


class ReportLocale(StrEnum):
    RU = 'ru'
    EN = 'en'


class ReportHTMLTemplate(StrEnum):
    NIST = 'nist'
    OUD4 = 'oud4'
    OWASP = 'owasp'
    OWASP_MOBILE = 'owasp_mobile'
    PCIDSS = 'pcidss'
    PLAIN = 'plain'
    SANS = 'sans'


ReturnType = TypeVar('ReturnType')
