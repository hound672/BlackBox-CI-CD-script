import time
import urllib.parse
from collections.abc import Callable
from functools import wraps
from typing import Any, cast

import httpx

from blackbox_ci.auth_profiles import build_auth_profile_body
from blackbox_ci.blackbox_api import BlackBoxAPI
from blackbox_ci.consts import (
    AUTO_CREATE_OPTION,
    HTML_TEMPLATES_MAP,
    IDLE_SCAN_STATUSES,
    PAGE_VULNS_LIMIT,
    RESET_API_PROFILE,
    RESET_AUTH_PROFILE,
    TARGET_URL_OPTION,
)
from blackbox_ci.errors import BlackBoxError, BlackBoxHTTPError, BlackBoxUrlError
from blackbox_ci.files import save_report_content
from blackbox_ci.generated.models.group_type import GroupType
from blackbox_ci.generated.models.scan_status import ScanStatus
from blackbox_ci.generated.models.severity import Severity
from blackbox_ci.generated.models.site_schema import SiteSchema
from blackbox_ci.generated.models.site_settings_info_schema import SiteSettingsInfoSchema
from blackbox_ci.generated.models.vuln_cve_approved_schema import VulnCVEApprovedSchema
from blackbox_ci.generated.models.vuln_cve_schema import VulnCVESchema
from blackbox_ci.generated.models.vuln_error_page_schema import VulnErrorPageSchema
from blackbox_ci.generated.models.vuln_group_schema import VulnGroupSchema
from blackbox_ci.generated.models.vuln_trending_schema import VulnTrendingSchema
from blackbox_ci.generated.models.vuln_we_schema import VulnWESchema
from blackbox_ci.generated.models.vulnerability_issue import VulnerabilityIssue
from blackbox_ci.types import (
    ErrorReport,
    GroupCve,
    GroupErrorPage,
    GroupIssue,
    ReportExtension,
    ReportLocale,
    ReportScanStatus,
    ReportTemplateShortname,
    ReturnType,
    ScanReport,
    TargetVulns,
    VulnCve,
    VulnErrorPage,
    VulnIssue,
)
from blackbox_ci.urls import normalize_url

IssueVuln = VulnWESchema | VulnTrendingSchema
CveVuln = VulnCVESchema | VulnCVEApprovedSchema


def ensure_attrs_set(
    *attrs: str,
) -> Callable[[Callable[..., ReturnType]], Callable[..., ReturnType]]:
    def decorator(func: Callable[..., ReturnType]) -> Callable[..., ReturnType]:
        @wraps(func)
        def wrapper(self: 'BlackBoxOperator', *args: Any, **kwargs: Any) -> ReturnType:
            if not all(hasattr(self, attr) for attr in attrs):
                verbose = ', '.join(attrs)
                raise RuntimeError(f'{verbose} not set')
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


class BlackBoxOperator:
    _site_uuid: str
    _scan_uuid: str
    _group_uuid: str

    def __init__(self, *, url: str, api: BlackBoxAPI) -> None:
        self._ui_base_url = url
        self._api = api
        self._scan_finished: bool = False

    def set_user_group(self, *, group_uuid: str | None) -> None:
        user_type_groups = [
            group
            for group in self._api.get_groups()
            if group.type_ == GroupType.USER and (group_uuid is None or group.uuid == group_uuid)
        ]
        if len(user_type_groups) == 1:
            group_uuid = user_type_groups[0].uuid
        elif group_uuid is None:
            raise BlackBoxError(
                'the group UUID for site is required, use UI to create new group or choose existing one',
            )
        else:
            raise BlackBoxError(
                'the group with the UUID specified was not found, use UI to create new or choose existing one',
            )
        self._group_uuid = group_uuid

    @ensure_attrs_set('_group_uuid')
    def get_target(self, *, url: str) -> SiteSchema | None:
        normalized_url = normalize_url(url)
        sites = self._api.get_sites()
        for site in sites:
            if site.url == normalized_url and site.group.uuid == self._group_uuid:
                return site
        return None

    @ensure_attrs_set('_site_uuid')
    def set_scan(self, *, scan_uuid: str | None) -> None:
        site = self._api.get_site(site_uuid=self._site_uuid)
        last_scan = site.last_scan
        if last_scan is None:
            raise BlackBoxError('this site has not yet been scanned')

        if scan_uuid and scan_uuid != last_scan.uuid:
            scan = self._api.get_scan(scan_uuid=scan_uuid)
            self._scan_uuid = scan_uuid
            self._scan_finished = scan.status in IDLE_SCAN_STATUSES
        else:
            self._scan_uuid = last_scan.uuid
            self._scan_finished = last_scan.status in IDLE_SCAN_STATUSES

    def set_target(
        self,
        *,
        url: str | None,
        uuid: str | None,
        group_uuid: str | None,
        auto_create: bool,
    ) -> None:
        if uuid:
            self.set_target_by_uuid(uuid=uuid, group_uuid=group_uuid)
        elif url:
            self.set_user_group(group_uuid=group_uuid)
            self.set_target_by_url(url=url, auto_create=auto_create)
        else:
            raise RuntimeError('uuid or url required to set target')

    def set_target_by_uuid(self, *, uuid: str, group_uuid: str | None) -> None:
        if group_uuid:
            self.set_user_group(group_uuid=group_uuid)  # ensure group exists
        sites = self._api.get_sites()
        for site in sites:
            if str(site.uuid) == uuid and (not group_uuid or site.group.uuid == group_uuid):
                self._group_uuid = site.group.uuid
                self._site_uuid = uuid
                return

        group_verbose = ' in the group' if group_uuid else ''
        raise BlackBoxError(
            f'the site with the UUID specified was not found{group_verbose}, '
            'choose existing one via UI, use UI to create new one manually '
            f'or use {TARGET_URL_OPTION} option and {AUTO_CREATE_OPTION} flag '
            f'to do so automatically',
        )

    @ensure_attrs_set('_group_uuid')
    def set_target_by_url(self, *, url: str, auto_create: bool) -> None:
        site = self.get_target(url=url)
        if site is None:
            if not auto_create:
                raise BlackBoxError(
                    'the site with the URL specified was not found in the group, '
                    'use UI to create one manually, '
                    f'or use {AUTO_CREATE_OPTION} flag to do so automatically',
                )
            self._site_uuid = self._api.add_site(target_url=url, group_uuid=self._group_uuid)
        else:
            self._site_uuid = str(site.uuid)

    @ensure_attrs_set('_site_uuid')
    def set_site_settings(
        self,
        *,
        profile_uuid: str | None,
        auth_uuid: str | None,
        api_profile_uuid: str | None,
    ) -> None:
        current_settings = self._api.get_site_settings(site_uuid=self._site_uuid)
        new_profile_uuid = self._get_new_profile_uuid(current_settings=current_settings, profile_uuid=profile_uuid)
        new_auth_uuid = self._get_new_auth_uuid(current_settings=current_settings, auth_uuid=auth_uuid)
        new_api_profile_uuid = self._get_new_api_profile_uuid(
            current_settings=current_settings,
            api_profile_uuid=api_profile_uuid,
        )
        if self._is_settings_changed(
            current_settings=current_settings,
            new_profile_uuid=new_profile_uuid,
            new_auth_uuid=new_auth_uuid,
            new_api_profile_uuid=new_api_profile_uuid,
        ):
            self._api.set_site_settings(
                site_uuid=self._site_uuid,
                profile_uuid=new_profile_uuid,
                authentication_uuid=new_auth_uuid,
                api_profile_uuid=new_api_profile_uuid,
            )

    @ensure_attrs_set('_group_uuid')
    def create_auth_profile(self, *, auth_data: dict[str, str]) -> str:
        group = self._api.get_group(group_uuid=self._group_uuid)
        body = build_auth_profile_body(
            group_uuid=self._group_uuid,
            group_name=group.name,
            auth_data=auth_data,
        )
        return self._api.create_auth_profile(body=body)

    @ensure_attrs_set('_site_uuid')
    def is_target_busy(self) -> bool:
        site = self._api.get_site(site_uuid=self._site_uuid)
        last_scan = site.last_scan
        if last_scan is None:
            return False
        return last_scan.status not in IDLE_SCAN_STATUSES

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def is_scan_busy(self) -> bool:
        scan = self._api.get_scan(scan_uuid=self._scan_uuid)
        return scan.status not in IDLE_SCAN_STATUSES

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def is_scan_ok(self) -> bool:
        scan = self._api.get_scan(scan_uuid=self._scan_uuid)
        return scan.status == ScanStatus.FINISHED and scan.error_reason is None

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def get_scan_error_reason(self) -> str | None:
        scan = self._api.get_scan(scan_uuid=self._scan_uuid)
        return scan.error_reason

    @ensure_attrs_set('_site_uuid')
    def ensure_target_is_idle(self, *, previous: str) -> None:
        if not self.is_target_busy():
            return

        if previous == 'fail':
            raise BlackBoxError('the target is busy')

        if previous == 'stop':
            self._api.stop_scan(site_uuid=self._site_uuid)
        # previous is either 'stop' or 'wait'
        self._wait_for_target()

    @ensure_attrs_set('_site_uuid')
    def start_scan(self) -> None:
        self._scan_uuid = self._api.start_scan(site_uuid=self._site_uuid)
        self._scan_finished = False

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def get_scan_report(
        self,
        *,
        target_url: str | None,
        shared_link: bool,
        report_path: str | None,
        partial_results: bool = False,
    ) -> ScanReport:
        site = self._api.get_site(site_uuid=self._site_uuid)
        scan = self._api.get_scan(scan_uuid=self._scan_uuid)

        report: ScanReport = {
            'target_url': target_url if target_url else site.url,
            'target_uuid': self._site_uuid,
            'url': self._scan_url,
            'scan_status': self._report_scan_status(scan.status),
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
            'errors': None,
        }
        if self._scan_finished or partial_results:
            report['score'] = self._api.get_score(scan_uuid=self._scan_uuid)
            report['vulns'] = self._collect_vulns()
        if shared_link:
            report['sharedLink'] = self._create_shared_link()
        return report

    def get_error_report(
        self,
        *,
        target_url: str | None,
        target_uuid: str | None,
        shared_link: bool,
        report_path: str | None,
        error: BlackBoxError,
    ) -> ScanReport:
        errors = [self._convert_error_json(error=error)]
        report: ScanReport = {
            'target_url': target_url,
            'target_uuid': self._site_uuid if not target_uuid and hasattr(self, '_site_uuid') else target_uuid,
            'url': None,
            'scan_status': None,
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
            'errors': errors,
        }

        if hasattr(self, '_site_uuid') and hasattr(self, '_scan_uuid'):
            report['url'] = self._scan_url

            try:
                report['target_url'] = target_url if target_url else self._api.get_site(site_uuid=self._site_uuid).url
                scan = self._api.get_scan(scan_uuid=self._scan_uuid)
                report['scan_status'] = self._report_scan_status(scan.status)
                if shared_link:
                    report['sharedLink'] = self._create_shared_link()
                report['score'] = self._api.get_score(scan_uuid=self._scan_uuid)
                report['vulns'] = self._collect_vulns()
            except BlackBoxHTTPError as request_error:
                errors.append(self._convert_error_json(error=request_error))
        return report

    @classmethod
    def get_init_error_report(
        cls,
        *,
        target_url: str | None,
        target_uuid: str | None,
        report_path: str | None,
        error: BlackBoxError,
    ) -> ScanReport:
        errors = [cls._convert_error_json(error=error)]
        report: ScanReport = {
            'target_url': target_url,
            'target_uuid': target_uuid,
            'url': None,
            'scan_status': None,
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
            'errors': errors,
        }
        return report

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def generate_report_file(
        self,
        *,
        locale: ReportLocale,
        template_shortname: ReportTemplateShortname,
        output_dir: str,
    ) -> str:
        if not self._scan_finished:
            raise BlackBoxError('scan must be finished or stopped to generate report')

        if template_shortname in HTML_TEMPLATES_MAP:
            extension = ReportExtension.HTML
            report_content = self._api.get_html_report_content(
                scan_uuid=self._scan_uuid,
                locale=locale,
                template=HTML_TEMPLATES_MAP[template_shortname],
            )
        else:
            extension = ReportExtension.SARIF
            report_content = self._api.get_sarif_report_content(scan_uuid=self._scan_uuid, locale=locale)
        return save_report_content(
            report_dir=output_dir,
            report_content=report_content,
            target_name=self._api.get_site(site_uuid=self._site_uuid).name,
            extension=extension,
            locale=locale,
            template_shortname=template_shortname,
        )

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def wait_for_scan(self) -> None:
        while self.is_scan_busy():
            time.sleep(2.0)
        self._scan_finished = True
        if not self.is_scan_ok():
            error_reason: str | None = self.get_scan_error_reason()
            verbose = (
                f'the error reason is "{error_reason}"'
                if error_reason
                else f'scan status is "{ReportScanStatus.stopped.value}"'
            )
            raise BlackBoxError(f'the scan did not succeed, {verbose}, see UI for details: {self._scan_url}')

    @ensure_attrs_set('_site_uuid')
    def _wait_for_target(self) -> None:
        while self.is_target_busy():
            time.sleep(2.0)

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def _create_shared_link(self) -> str:
        shared_link_uuid = self._api.create_shared_link(scan_uuid=self._scan_uuid)
        return urllib.parse.urljoin(self._ui_base_url, f'/shared/{shared_link_uuid}')

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def _collect_vulns(self) -> TargetVulns:
        group_list = self._api.get_vuln_groups(scan_uuid=self._scan_uuid)
        vuln_report: TargetVulns = {
            'issue_groups': [],
            'error_page_groups': [],
            'cve_groups': [],
        }

        for group_info in group_list:
            issue_type = group_info.issue_type

            if issue_type == VulnerabilityIssue.ISSUE:
                vuln_report['issue_groups'].append(self._create_group_issue(group_info=group_info))
            elif issue_type == VulnerabilityIssue.ERROR_PAGE:
                vuln_report['error_page_groups'].append(self._create_group_error_page(group_info=group_info))
            elif issue_type == VulnerabilityIssue.CVE:
                vuln_report['cve_groups'].append(self._create_group_cve(group_info=group_info))

        return vuln_report

    def _create_group_issue(self, *, group_info: VulnGroupSchema) -> GroupIssue:
        group: GroupIssue = {
            'severity': group_info.severity.value,
            'category': group_info.category_locale_key.value,
            'group_title': group_info.group_title,
            'vulns': [],
        }
        if group_info.count == 1:
            group['vulns'].append(self._convert_issue(vuln=cast(IssueVuln, group_info.vulnerability)))
        else:
            request_key = cast(str, group_info.request_key)
            group['vulns'].extend(self._read_issue_vulns(request_key=request_key, severity=group_info.severity))
        return group

    def _create_group_error_page(self, *, group_info: VulnGroupSchema) -> GroupErrorPage:
        group: GroupErrorPage = {
            'group_title': group_info.group_title,
            'category': group_info.category_locale_key.value,
            'vulns': [],
        }
        if group_info.count == 1:
            group['vulns'].append(self._convert_error_page(vuln=cast(VulnErrorPageSchema, group_info.vulnerability)))
        else:
            request_key = cast(str, group_info.request_key)
            group['vulns'].extend(self._read_error_page_vulns(request_key=request_key))
        return group

    def _create_group_cve(self, *, group_info: VulnGroupSchema) -> GroupCve:
        group: GroupCve = {
            'category': group_info.category_locale_key.value,
            'group_title': group_info.group_title,
            'vulns': [],
        }
        if group_info.count == 1:
            group['vulns'].append(self._convert_cve(vuln=cast(CveVuln, group_info.vulnerability)))
        else:
            request_key = cast(str, group_info.request_key)
            group['vulns'].extend(self._read_cve_vulns(request_key=request_key))
        return group

    @staticmethod
    def _convert_issue(*, vuln: IssueVuln) -> VulnIssue:
        return {'url': vuln.url_full or ''}

    @staticmethod
    def _convert_error_page(*, vuln: VulnErrorPageSchema) -> VulnErrorPage:
        return {'url': vuln.url}

    @staticmethod
    def _convert_cve(*, vuln: CveVuln) -> VulnCve:
        return {'cve_id': vuln.cve_id, 'vector': vuln.cvss_vector}

    def _read_issue_vulns(self, *, request_key: str, severity: Severity) -> list[VulnIssue]:
        items = self._read_all_vulns(
            issue_type=VulnerabilityIssue.ISSUE,
            request_key=request_key,
            severity=severity,
        )
        return [self._convert_issue(vuln=cast(IssueVuln, item)) for item in items]

    def _read_error_page_vulns(self, *, request_key: str) -> list[VulnErrorPage]:
        items = self._read_all_vulns(
            issue_type=VulnerabilityIssue.ERROR_PAGE,
            request_key=request_key,
            severity=Severity.INFO,
        )
        return [self._convert_error_page(vuln=cast(VulnErrorPageSchema, item)) for item in items]

    def _read_cve_vulns(self, *, request_key: str) -> list[VulnCve]:
        items = self._read_all_vulns(
            issue_type=VulnerabilityIssue.CVE,
            request_key=request_key,
            severity=Severity.INFO,
        )
        return [self._convert_cve(vuln=cast(CveVuln, item)) for item in items]

    @ensure_attrs_set('_site_uuid', '_scan_uuid')
    def _read_all_vulns(
        self,
        *,
        issue_type: VulnerabilityIssue,
        request_key: str,
        severity: Severity,
    ) -> list[VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema | VulnWESchema]:
        vulns: list[VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema | VulnWESchema] = []
        page = 1  # page starts with 1
        while True:
            vuln_page = self._api.get_vuln_group_page(
                scan_uuid=self._scan_uuid,
                issue_type=issue_type,
                request_key=request_key,
                severity=severity,
                limit=PAGE_VULNS_LIMIT,
                page=page,
            )
            vulns.extend(vuln_page.items)
            if vuln_page.total_count <= vuln_page.current_page:
                break
            page += 1
        return vulns

    @staticmethod
    def _report_scan_status(status: ScanStatus) -> ReportScanStatus:
        if status in IDLE_SCAN_STATUSES:
            return ReportScanStatus(status.value)
        return ReportScanStatus.in_progress

    @staticmethod
    def _get_new_profile_uuid(*, current_settings: SiteSettingsInfoSchema, profile_uuid: str | None) -> str:
        if profile_uuid is None:
            return current_settings.profile.uuid
        return profile_uuid

    @staticmethod
    def _get_new_auth_uuid(*, current_settings: SiteSettingsInfoSchema, auth_uuid: str | None) -> str | None:
        if auth_uuid is None and current_settings.authentication is not None:
            return current_settings.authentication.uuid
        if auth_uuid == RESET_AUTH_PROFILE:
            return None
        return auth_uuid

    @staticmethod
    def _get_new_api_profile_uuid(
        *,
        current_settings: SiteSettingsInfoSchema,
        api_profile_uuid: str | None = None,
    ) -> str | None:
        if api_profile_uuid is None and current_settings.api_profile is not None:
            return current_settings.api_profile.uuid
        if api_profile_uuid == RESET_API_PROFILE:
            return None
        return api_profile_uuid

    @staticmethod
    def _is_settings_changed(
        *,
        current_settings: SiteSettingsInfoSchema,
        new_profile_uuid: str,
        new_auth_uuid: str | None,
        new_api_profile_uuid: str | None,
    ) -> bool:
        if current_settings.profile.uuid != new_profile_uuid:
            return True
        current_auth_uuid = current_settings.authentication.uuid if current_settings.authentication else None
        if current_auth_uuid != new_auth_uuid:
            return True
        current_api_uuid = current_settings.api_profile.uuid if current_settings.api_profile else None
        return current_api_uuid != new_api_profile_uuid

    @staticmethod
    def _convert_error_json(*, error: BlackBoxError) -> ErrorReport:
        error_report: ErrorReport
        if isinstance(error, BlackBoxHTTPError):
            error_report = {
                'short_info': 'BlackBox API call failed',
                'message': str(error),
                'json': None,
            }
            if (
                isinstance(error.response, httpx.Response)
                and error.response.headers.get('Content-Type') == 'application/json'
            ):
                error_report['json'] = error.response.json()
        elif isinstance(error, BlackBoxUrlError):
            error_report = {
                'short_info': 'Invalid BlackBox url or server connection failed',
                'message': str(error),
                'json': None,
            }
        else:
            error_report = {
                'short_info': 'BlackBox error',
                'message': str(error),
                'json': None,
            }

        return error_report

    @property
    def _scan_url(self) -> str:
        return urllib.parse.urljoin(
            self._ui_base_url,
            f'/sites/{self._site_uuid}/scans/{self._scan_uuid}',
        )
