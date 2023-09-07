import time
import typing
import urllib.parse

from blackbox_ci.blackbox_api import BlackBoxAPI
from blackbox_ci.consts import (
    AUTO_CREATE_OPTION,
    HTML_REPORT_SHORTNAMES,
    HTML_TEMPLATES_MAP,
    IDLE_SCAN_STATUSES,
    PAGE_VULNS_LIMIT,
    RESET_API_PROFILE,
    RESET_AUTH_PROFILE,
    SCAN_STATUS_FINISHED,
)
from blackbox_ci.errors import BlackBoxError
from blackbox_ci.files import save_report_content
from blackbox_ci.types import (
    APIProfile,
    AuthenticationProfile,
    GroupCve,
    GroupErrorPage,
    GroupIssue,
    ReportExtension,
    ReportLocale,
    ReportTemplateShortname,
    ScanProfile,
    ScanReport,
    Site,
    SiteSettings,
    TargetVulns,
    VulnCommon,
    VulnCve,
    VulnErrorPage,
    VulnGroup,
    VulnIssue,
)
from blackbox_ci.urls import normalize_url


class BlackBoxOperator:
    def __init__(self, url: str, api: BlackBoxAPI) -> None:
        self._ui_base_url = url
        self._api = api
        self._site_uuid: typing.Optional[str] = None
        self._scan_id: typing.Optional[int] = None
        self._group_uuid: typing.Optional[str] = None
        self._scan_finished: bool = False

    def set_user_group(self, group_uuid: typing.Optional[str]) -> None:
        groups = self._api.get_user_groups()
        if group_uuid is None and len(groups) == 1:
            group_uuid = groups[0]['uuid']
        elif group_uuid is None:
            raise BlackBoxError(
                'the group UUID for site is required, '
                'use UI to create new group or choose existing one'
            )
        elif not any(group['uuid'] == group_uuid for group in groups):
            raise BlackBoxError(
                'the group with the UUID specified was not found, '
                'use UI to create new or choose existing one'
            )
        self._group_uuid = group_uuid

    def get_target(self, url: str) -> typing.Optional[Site]:
        if not self._group_uuid:
            raise RuntimeError('group not set')

        normalized_url = normalize_url(url)
        sites = self._api.get_sites()
        for site in sites:
            if (
                site['url'] == normalized_url
                and site['group']['uuid'] == self._group_uuid
            ):
                return site
        return None

    def set_target(self, url: str, auto_create: bool) -> None:
        if not self._group_uuid:
            raise RuntimeError('group not set')

        site = self.get_target(url)
        if site is None:
            if not auto_create:
                raise BlackBoxError(
                    'the site with the URL specified was not found in the group, '
                    'use UI to create one manually, '
                    f'or use {AUTO_CREATE_OPTION} flag to do so automatically'
                )
            self._site_uuid = self._api.add_site(url, self._group_uuid)
        else:
            self._site_uuid = site['uuid']

    def set_site_settings(
        self,
        profile_uuid: typing.Optional[str],
        auth_uuid: typing.Optional[str],
        api_profile_uuid: typing.Optional[str],
    ) -> None:
        if not self._site_uuid:
            raise RuntimeError('target not set')

        current_settings = self._api.get_site_settings(self._site_uuid)
        new_profile_uuid = self._get_new_profile_uuid(current_settings, profile_uuid)
        new_auth_uuid = self._get_new_auth_uuid(current_settings, auth_uuid)
        new_api_profile_uuid = self._get_new_api_profile_uuid(
            current_settings, api_profile_uuid
        )
        if self._is_settings_changed(
            current_settings, new_profile_uuid, new_auth_uuid, new_api_profile_uuid
        ):
            self._api.set_site_settings(
                site_uuid=self._site_uuid,
                profile_uuid=new_profile_uuid,
                authentication_uuid=new_auth_uuid,
                api_profile_uuid=new_api_profile_uuid,
            )

    def is_target_busy(self) -> bool:
        if not self._site_uuid:
            raise RuntimeError('target not set')

        site = self._api.get_site(self._site_uuid)
        last_scan = site['lastScan']
        if not last_scan:
            return False
        return last_scan['status'] not in IDLE_SCAN_STATUSES

    def is_scan_busy(self) -> bool:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        scan = self._api.get_scan(self._site_uuid, self._scan_id)
        return scan['status'] not in IDLE_SCAN_STATUSES

    def is_scan_ok(self) -> bool:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        scan = self._api.get_scan(self._site_uuid, self._scan_id)
        return scan['status'] == SCAN_STATUS_FINISHED and scan['errorReason'] is None

    def ensure_target_is_idle(self, previous: str) -> None:
        if not self._site_uuid:
            raise RuntimeError('target not set')

        if not self.is_target_busy():
            return

        if previous == 'fail':
            raise BlackBoxError('the target is busy')

        if previous == 'stop':
            self._api.stop_scan(self._site_uuid)
        # previous is either 'stop' or 'wait'
        self._wait_for_target()

    def start_scan(self) -> None:
        if not self._site_uuid:
            raise RuntimeError('target not set')

        self._scan_id = self._api.start_scan(self._site_uuid)
        self._scan_finished = False

    def get_scan_report(
        self, target_url: str, share_link: bool, report_path: typing.Optional[str]
    ) -> ScanReport:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        report: ScanReport = {
            'target_url': target_url,
            'url': self._scan_url,
            'score': None,
            'sharedLink': None,
            'report_path': report_path,
            'vulns': None,
        }
        if self._scan_finished:
            report['score'] = self._api.get_score(self._site_uuid, self._scan_id)
            report['vulns'] = self._collect_vulns()
        if share_link:
            report['sharedLink'] = self._create_shared_link()
        return report

    def generate_report_file(
        self,
        locale: ReportLocale,
        template_shortname: ReportTemplateShortname,
        output_dir: str,
    ) -> str:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        if not self._scan_finished:
            raise RuntimeError('scan not finished')

        if template_shortname in HTML_REPORT_SHORTNAMES:
            extension = ReportExtension.HTML
            report_content = self._api.get_html_report_content(
                site_uuid=self._site_uuid,
                scan_id=self._scan_id,
                locale=locale,
                template=HTML_TEMPLATES_MAP[template_shortname],
            )
        else:
            extension = ReportExtension.SARIF
            report_content = self._api.get_sarif_report_content(
                site_uuid=self._site_uuid, scan_id=self._scan_id, locale=locale
            )
        report_path = save_report_content(
            report_dir=output_dir,
            report_content=report_content,
            target_name=self._api.get_site(self._site_uuid)['name'],
            extension=extension,
            locale=locale,
            template_shortname=template_shortname,
        )
        return report_path

    def wait_for_scan(self) -> None:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        while self.is_scan_busy():
            time.sleep(2.0)
        self._scan_finished = True
        if not self.is_scan_ok():
            raise BlackBoxError(
                f'the scan did not succeed, '
                f'see UI for the error reason: {self._scan_url}'
            )

    def _wait_for_target(self) -> None:
        if not self._site_uuid:
            raise RuntimeError('target not set')

        while self.is_target_busy():
            time.sleep(2.0)

    def _create_shared_link(self) -> str:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        shared_link_uuid = self._api.create_shared_link(self._site_uuid, self._scan_id)
        shared_link = urllib.parse.urljoin(
            self._ui_base_url, f'/shared/{shared_link_uuid}'
        )
        return shared_link

    def _collect_vulns(  # noqa: C901
        self,
    ) -> TargetVulns:
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        group_list = self._api.get_vuln_groups(self._site_uuid, self._scan_id)
        vuln_report: TargetVulns = {
            'issue_groups': [],
            'error_page_groups': [],
            'cve_groups': [],
        }

        for group_info in group_list:
            issue_type = group_info['issueType']

            if issue_type == 'issue':
                issue_group = self._create_group_issue(group_info)
                vuln_report['issue_groups'].append(issue_group)

            elif issue_type == 'error_page':
                error_page_group = self._create_group_error_page(group_info)
                vuln_report['error_page_groups'].append(error_page_group)

            elif issue_type == 'cve':
                cve_group = self._create_group_cve(group_info)
                vuln_report['cve_groups'].append(cve_group)

        return vuln_report

    def _create_group_issue(self, group_info: VulnGroup) -> GroupIssue:
        group: GroupIssue = {
            'severity': group_info['severity'],
            'category': group_info['categoryLocaleKey'],
            'group_title': group_info['groupTitle'],
            'vulns': [],
        }

        request_key = group_info['requestKey']
        request_key = typing.cast(str, request_key)

        severity = group_info['severity']
        count = group_info['count']

        if count == 1:
            group['vulns'].append(self._convert_issue(group_info['vulnerability']))
        else:
            group['vulns'].extend(
                self._read_issue_vulns(request_key=request_key, severity=severity)
            )
        return group

    def _create_group_error_page(self, group_info: VulnGroup) -> GroupErrorPage:
        group: GroupErrorPage = {
            'group_title': group_info['groupTitle'],
            'category': group_info['categoryLocaleKey'],
            'vulns': [],
        }

        request_key = group_info['requestKey']
        request_key = typing.cast(str, request_key)

        count = group_info['count']

        if count == 1:
            group['vulns'].append(self._convert_error_page(group_info['vulnerability']))
        else:
            group['vulns'].extend(self._read_error_page_vulns(request_key=request_key))
        return group

    def _create_group_cve(self, group_info: VulnGroup) -> GroupCve:
        group: GroupCve = {
            'category': group_info['categoryLocaleKey'],
            'group_title': group_info['groupTitle'],
            'vulns': [],
        }

        request_key = group_info['requestKey']
        request_key = typing.cast(str, request_key)

        count = group_info['count']

        if count == 1:
            group['vulns'].append(self._convert_cve(group_info['vulnerability']))
        else:
            group['vulns'].extend(self._read_cve_vulns(request_key=request_key))
        return group

    def _convert_issue(self, vuln: VulnCommon) -> VulnIssue:
        v: VulnIssue = {
            'url': vuln['urlFull'],
        }
        return v

    def _convert_error_page(self, vuln: VulnCommon) -> VulnErrorPage:
        v: VulnErrorPage = {
            'url': vuln['url'],
        }
        return v

    def _convert_cve(self, vuln: VulnCommon) -> VulnCve:
        v: VulnCve = {
            'cve_id': vuln['cveId'],
            'vector': vuln['cvssVector'],
        }
        return v

    def _read_issue_vulns(
        self, request_key: str, severity: str
    ) -> typing.List[VulnIssue]:
        vulns = self._read_all_vulns(
            issue_type='issue',
            request_key=request_key,
            severity=severity,
        )

        return [self._convert_issue(v) for v in vulns]

    def _read_error_page_vulns(self, request_key: str) -> typing.List[VulnErrorPage]:
        vulns = self._read_all_vulns(
            issue_type='error_page',
            request_key=request_key,
            severity='info',
        )

        return [self._convert_error_page(v) for v in vulns]

    def _read_cve_vulns(self, request_key: str) -> typing.List[VulnCve]:
        vulns = self._read_all_vulns(
            issue_type='cve',
            request_key=request_key,
            severity='info',
        )

        return [self._convert_cve(v) for v in vulns]

    def _read_all_vulns(
        self, *, issue_type: str, request_key: str, severity: str
    ) -> typing.List[VulnCommon]:
        """
        Just wrapper for reading all vulns
        """
        if not self._site_uuid or not self._scan_id:
            raise RuntimeError('target or scan not set')

        vulns: typing.List[VulnCommon] = []
        has_next_page = True
        page = 1  # page starts with 1
        while has_next_page is True:
            vuln_page = self._api.get_vuln_group_page(
                self._site_uuid,
                self._scan_id,
                issue_type=issue_type,
                request_key=request_key,
                severity=severity,
                limit=PAGE_VULNS_LIMIT,
                page=page,
            )
            vulns.extend(vuln_page['items'])
            has_next_page = vuln_page['hasNextPage']
            page += 1

        return vulns

    def _get_new_profile_uuid(
        self, current_settings: SiteSettings, profile_uuid: typing.Optional[str]
    ) -> str:
        if profile_uuid is None:
            profile_uuid = current_settings['profile']['uuid']
        return profile_uuid

    def _get_new_auth_uuid(
        self, current_settings: SiteSettings, auth_uuid: typing.Optional[str]
    ) -> typing.Optional[str]:
        if auth_uuid is None and current_settings['authentication'] is not None:
            auth_uuid = current_settings['authentication']['uuid']
        elif auth_uuid == RESET_AUTH_PROFILE:
            auth_uuid = None
        return auth_uuid

    def _get_new_api_profile_uuid(
        self,
        current_settings: SiteSettings,
        api_profile_uuid: typing.Optional[str] = None,
    ) -> typing.Optional[str]:
        if api_profile_uuid is None and current_settings['apiProfile'] is not None:
            api_profile_uuid = current_settings['apiProfile']['uuid']
        elif api_profile_uuid == RESET_API_PROFILE:
            api_profile_uuid = None
        return api_profile_uuid

    def _is_scan_profile_changed(
        self, current_scan_profile: ScanProfile, new_profile_uuid: str
    ) -> bool:
        return current_scan_profile['uuid'] != new_profile_uuid

    def _is_auth_profile_changed(
        self,
        current_auth_profile: typing.Optional[AuthenticationProfile],
        new_auth_uuid: typing.Optional[str],
    ) -> bool:
        return (
            current_auth_profile is not None
            and new_auth_uuid != current_auth_profile['uuid']
            or current_auth_profile is None
            and new_auth_uuid is not None
        )

    def _is_api_profile_changed(
        self,
        current_api_profile: typing.Optional[APIProfile],
        new_api_uuid: typing.Optional[str],
    ) -> bool:
        return (
            current_api_profile is not None
            and new_api_uuid != current_api_profile['uuid']
            or current_api_profile is None
            and new_api_uuid is not None
        )

    def _is_settings_changed(
        self,
        current_settings: SiteSettings,
        new_profile_uuid: str,
        new_auth_uuid: typing.Optional[str],
        new_api_profile_uuid: typing.Optional[str],
    ) -> bool:
        return (
            self._is_scan_profile_changed(current_settings['profile'], new_profile_uuid)
            or self._is_auth_profile_changed(
                current_settings['authentication'], new_auth_uuid
            )
            or self._is_api_profile_changed(
                current_settings['apiProfile'], new_api_profile_uuid
            )
        )

    @property
    def _scan_url(self) -> str:
        return urllib.parse.urljoin(
            self._ui_base_url,
            f'/sites/{self._site_uuid}/scans/{self._scan_id}',
        )
