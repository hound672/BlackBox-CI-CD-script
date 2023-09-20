import typing

from blackbox_ci.types import ReportHTMLTemplate, ReportTemplateShortname, ScanStatus

# transport consts
SERVER_RETRY_MAX_ATTEMPTS = 5
SERVER_RETRY_BACKOFF_FACTOR = 0.5
SERVER_RETRY_STATUSES = (502, 503, 504)

# exit codes
SUCCESS_EXIT_CODE = 0
ERROR_EXIT_CODE = 1
SCORE_FAIL_EXIT_CODE = 3

# settings consts
RESET_AUTH_PROFILE = 'RESET'
RESET_API_PROFILE = 'RESET'

# url consts
STANDARD_PORT_SCHEMES = {
    80: 'http',
    443: 'https',
}
DEFAULT_SCHEME = 'https'

# scan status consts
SCAN_STATUS_FINISHED: ScanStatus = 'FINISHED'
IDLE_SCAN_STATUSES: typing.Tuple[ScanStatus, ...] = ('STOPPED', 'FINISHED')

# vulns consts
PAGE_VULNS_LIMIT = 100

# report consts
HTML_REPORT_SHORTNAMES = (
    ReportTemplateShortname.HTML,
    ReportTemplateShortname.NIST,
    ReportTemplateShortname.OUD4,
    ReportTemplateShortname.OWASP,
    ReportTemplateShortname.OWASP_MOBILE,
    ReportTemplateShortname.PCIDSS,
    ReportTemplateShortname.SANS,
)
SARIF_REPORT_SHORTNAMES = (ReportTemplateShortname.SARIF,)
HTML_TEMPLATES_MAP = {
    ReportTemplateShortname.HTML: ReportHTMLTemplate.PLAIN,
    ReportTemplateShortname.NIST: ReportHTMLTemplate.NIST,
    ReportTemplateShortname.OUD4: ReportHTMLTemplate.OUD4,
    ReportTemplateShortname.OWASP: ReportHTMLTemplate.OWASP,
    ReportTemplateShortname.OWASP_MOBILE: ReportHTMLTemplate.OWASP_MOBILE,
    ReportTemplateShortname.PCIDSS: ReportHTMLTemplate.PCIDSS,
    ReportTemplateShortname.SANS: ReportHTMLTemplate.SANS,
}
REPORT_FILENAME_DATETIME_FORMAT = '%Y%m%d_%H%M%S'

# option consts
BLACKBOX_URL_OPTION = '--blackbox-url'
BLACKBOX_URL_ENV = 'BLACKBOX_URL'
BLACKBOX_API_TOKEN_OPTION = '--blackbox-api-token'  # noqa: S105
BLACKBOX_API_TOKEN_ENV = 'BLACKBOX_API_TOKEN'  # noqa: S105
TARGET_URL_OPTION = '--target-url'
TARGET_URL_ENV = 'TARGET_URL'
TARGET_FILE_OPTION = '--target-file'
TARGET_FILE_ENV = 'TARGET_FILE'
GROUP_UUID_OPTION = '--group-uuid'
GROUP_UUID_ENV = 'GROUP_UUID'
IGNORE_SSL_OPTION = '--ignore-ssl'
IGNORE_SSL_ENV = 'IGNORE_SSL'
AUTO_CREATE_OPTION = '--auto-create'
PREVIOUS_OPTION = '--previous'
NO_WAIT_OPTION = '--no-wait'
SHARED_LINK_OPTION = '--shared-link'
SCAN_PROFILE_OPTION = '--scan-profile'
SCAN_PROFILE_ENV = 'SCAN_PROFILE'
AUTH_PROFILE_OPTION = '--auth-profile'
AUTH_PROFILE_ENV = 'AUTH_PROFILE'
API_SCHEMA_OPTION = '--api-schema'
API_SCHEMA_ENV = 'API_SCHEMA'
FAIL_UNDER_SCORE_OPTION = '--fail-under-score'
REPORT_DIR_OPTION = '--report-dir'
REPORT_TEMPLATE_OPTION = '--report-template'
REPORT_LOCALE_OPTION = '--report-locale'
