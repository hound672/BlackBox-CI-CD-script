import urllib.parse
from collections.abc import Callable
from typing import Any, cast
from uuid import UUID

import httpx

from blackbox_ci.errors import (
    BlackBoxConnectionError,
    BlackBoxError,
    BlackBoxHTTPError,
    BlackBoxInvalidUrlError,
    BlackBoxRequestError,
    BlackBoxSSLError,
)
from blackbox_ci.generated import Client
from blackbox_ci.generated.api.v1_auth_profile import api_v1_auth_profiles_post
from blackbox_ci.generated.api.v1_group import (
    api_v1_groups_get_all,
    api_v1_groups_group_uuid_get,
)
from blackbox_ci.generated.api.v1_report import (
    api_v1_reports_html_scan_uuid_html,
    api_v1_reports_sarif_scan_uuid_sarif,
)
from blackbox_ci.generated.api.v1_scan import (
    api_v1_scans_scan_uuid_info,
    api_v1_sites_site_uuid_start_start,
    api_v1_sites_site_uuid_stop_stop,
)
from blackbox_ci.generated.api.v1_shared_link import (
    api_v1_scans_scan_uuid_shared_create,
)
from blackbox_ci.generated.api.v1_site import (
    api_v1_sites_add_add,
    api_v1_sites_get_all,
    api_v1_sites_site_uuid_get,
    api_v1_sites_site_uuid_settings_get_settings,
    api_v1_sites_site_uuid_settings_set_settings,
)
from blackbox_ci.generated.api.v1_vulnerabilities import (
    api_v1_scans_scan_uuid_vulnerabilities_get_groups,
    api_v1_scans_scan_uuid_vulnerabilities_issue_type_group_name_severity_get_in_group as api_vulns_in_group,
)
from blackbox_ci.generated.models.auth_profile_create_schema import AuthProfileCreateSchema
from blackbox_ci.generated.models.auth_profile_short_info_schema import AuthProfileShortInfoSchema
from blackbox_ci.generated.models.group_role_full_info_schema import GroupRoleFullInfoSchema
from blackbox_ci.generated.models.group_role_info_schema import GroupRoleInfoSchema
from blackbox_ci.generated.models.pagination_schema_vuln_in_group_schema import PaginationSchemaVulnInGroupSchema
from blackbox_ci.generated.models.report_lang_enum import ReportLangEnum
from blackbox_ci.generated.models.scan_queue_profiles_schema import ScanQueueProfilesSchema
from blackbox_ci.generated.models.severity import Severity
from blackbox_ci.generated.models.shared_link_create_schema import SharedLinkCreateSchema
from blackbox_ci.generated.models.shared_link_schema import SharedLinkSchema
from blackbox_ci.generated.models.site_create_schema import SiteCreateSchema
from blackbox_ci.generated.models.site_schema import SiteSchema
from blackbox_ci.generated.models.site_set_settings_schema import SiteSetSettingsSchema
from blackbox_ci.generated.models.site_settings_info_schema import SiteSettingsInfoSchema
from blackbox_ci.generated.models.template_name import TemplateName
from blackbox_ci.generated.models.vuln_group_schema import VulnGroupSchema
from blackbox_ci.generated.models.vulnerability_issue import VulnerabilityIssue
from blackbox_ci.generated.types import Response
from blackbox_ci.types import ReportHTMLTemplate, ReportLocale


class BlackBoxAPI:
    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        ignore_ssl: bool,
        retries: int = 0,
    ) -> None:
        self._auth_header = f'Basic {api_token}'
        client_base_url = urllib.parse.urljoin(base_url, 'app')
        transport = httpx.HTTPTransport(retries=retries, verify=not ignore_ssl)
        self._verify_base_url(base_url, ignore_ssl=ignore_ssl)
        self._client = Client(
            base_url=client_base_url,
            headers={'Authorization': self._auth_header},
            verify_ssl=not ignore_ssl,
            raise_on_unexpected_status=False,
            httpx_args={'transport': transport},
        )

    # ----- groups -----

    def get_groups(self) -> list[GroupRoleInfoSchema]:
        resp = self._call(
            lambda: api_v1_groups_get_all.sync_detailed(client=self._client, authorization=self._auth_header),
        )
        return cast(list[GroupRoleInfoSchema], resp.parsed)

    def get_group(self, *, group_uuid: str) -> GroupRoleFullInfoSchema:
        resp = self._call(
            lambda: api_v1_groups_group_uuid_get.sync_detailed(
                group_uuid=UUID(group_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
        )
        return cast(GroupRoleFullInfoSchema, resp.parsed)

    # ----- sites -----

    def get_sites(self) -> list[SiteSchema]:
        resp = self._call(
            lambda: api_v1_sites_get_all.sync_detailed(client=self._client, authorization=self._auth_header),
        )
        return cast(list[SiteSchema], resp.parsed)

    def get_site(self, *, site_uuid: str) -> SiteSchema:
        resp = self._call(
            lambda: api_v1_sites_site_uuid_get.sync_detailed(
                site_uuid=UUID(site_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
        )
        return cast(SiteSchema, resp.parsed)

    def add_site(self, *, target_url: str, group_uuid: str) -> str:
        body = SiteCreateSchema(url=target_url, group_uuid=UUID(group_uuid))
        resp = self._call(
            lambda: api_v1_sites_add_add.sync_detailed(client=self._client, body=body, authorization=self._auth_header),
        )
        return str(cast(SiteSchema, resp.parsed).uuid)

    def set_site_settings(
        self,
        *,
        site_uuid: str,
        profile_uuid: str,
        authentication_uuid: str | None,
        api_profile_uuid: str | None,
    ) -> None:
        body = SiteSetSettingsSchema(
            profile_uuid=UUID(profile_uuid),
            authentication_uuid=UUID(authentication_uuid) if authentication_uuid else None,
            api_profile_uuid=UUID(api_profile_uuid) if api_profile_uuid else None,
        )
        self._call(
            lambda: api_v1_sites_site_uuid_settings_set_settings.sync_detailed(
                site_uuid=UUID(site_uuid),
                client=self._client,
                body=body,
                authorization=self._auth_header,
            ),
        )

    def get_site_settings(self, *, site_uuid: str) -> SiteSettingsInfoSchema:
        resp = self._call(
            lambda: api_v1_sites_site_uuid_settings_get_settings.sync_detailed(
                site_uuid=UUID(site_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
        )
        return cast(SiteSettingsInfoSchema, resp.parsed)

    # ----- scans -----

    def start_scan(self, *, site_uuid: str) -> str:
        resp = self._call(
            lambda: api_v1_sites_site_uuid_start_start.sync_detailed(
                site_uuid=UUID(site_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
        )
        return cast(ScanQueueProfilesSchema, resp.parsed).uuid

    def stop_scan(self, *, site_uuid: str) -> None:
        self._call(
            lambda: api_v1_sites_site_uuid_stop_stop.sync_detailed(
                site_uuid=UUID(site_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
        )

    def get_scan(self, *, scan_uuid: str) -> ScanQueueProfilesSchema:
        resp = self._call(
            lambda: api_v1_scans_scan_uuid_info.sync_detailed(
                scan_uuid=UUID(scan_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
            not_found_msg='the specified scan was not found',
        )
        return cast(ScanQueueProfilesSchema, resp.parsed)

    def get_score(self, *, scan_uuid: str) -> float | None:
        return self.get_scan(scan_uuid=scan_uuid).score

    def create_shared_link(self, *, scan_uuid: str) -> str:
        resp = self._call(
            lambda: api_v1_scans_scan_uuid_shared_create.sync_detailed(
                scan_uuid=UUID(scan_uuid),
                client=self._client,
                body=SharedLinkCreateSchema(),
                authorization=self._auth_header,
            ),
        )
        return cast(SharedLinkSchema, resp.parsed).uuid

    # ----- vulnerabilities -----

    def get_vuln_groups(self, *, scan_uuid: str) -> list[VulnGroupSchema]:
        resp = self._call(
            lambda: api_v1_scans_scan_uuid_vulnerabilities_get_groups.sync_detailed(
                scan_uuid=UUID(scan_uuid),
                client=self._client,
                authorization=self._auth_header,
            ),
        )
        return cast(list[VulnGroupSchema], resp.parsed)

    def get_vuln_group_page(
        self,
        *,
        scan_uuid: str,
        issue_type: VulnerabilityIssue,
        request_key: str,
        severity: Severity,
        limit: int,
        page: int,
    ) -> PaginationSchemaVulnInGroupSchema:
        resp = self._call(
            lambda: api_vulns_in_group.sync_detailed(
                scan_uuid=UUID(scan_uuid),
                issue_type=issue_type,
                group_name=request_key,
                severity=severity,
                client=self._client,
                authorization=self._auth_header,
                limit=limit,
                page=page,
            ),
        )
        return cast(PaginationSchemaVulnInGroupSchema, resp.parsed)

    # ----- auth profiles -----

    def create_auth_profile(self, *, body: AuthProfileCreateSchema) -> str:
        resp = self._call(
            lambda: api_v1_auth_profiles_post.sync_detailed(
                client=self._client,
                body=body,
                authorization=self._auth_header,
            ),
        )
        return cast(AuthProfileShortInfoSchema, resp.parsed).uuid

    # ----- reports -----

    def get_sarif_report_content(self, *, scan_uuid: str, locale: ReportLocale) -> bytes:
        resp = self._call(
            lambda: api_v1_reports_sarif_scan_uuid_sarif.sync_detailed(
                scan_uuid=UUID(scan_uuid),
                client=self._client,
                locale=ReportLangEnum(locale.value),
            ),
        )
        return bytes(resp.content)

    def get_html_report_content(
        self,
        *,
        scan_uuid: str,
        locale: ReportLocale,
        template: ReportHTMLTemplate,
    ) -> bytes:
        resp = self._call(
            lambda: api_v1_reports_html_scan_uuid_html.sync_detailed(
                scan_uuid=UUID(scan_uuid),
                client=self._client,
                locale=ReportLangEnum(locale.value),
                template=TemplateName(template.value),
            ),
        )
        return bytes(resp.content)

    # ----- helpers -----

    def _call(
        self,
        fn: Callable[[], Response[Any]],
        *,
        not_found_msg: str | None = None,
    ) -> Response[Any]:
        try:
            resp = fn()
        except httpx.ConnectError as ex:
            raise BlackBoxConnectionError(str(ex)) from ex
        except httpx.RequestError as ex:
            raise BlackBoxRequestError(f'Error while handling request {ex}') from ex
        status = int(resp.status_code)
        if httpx.codes.is_success(status):
            return resp
        if not_found_msg is not None and status == httpx.codes.NOT_FOUND:
            raise BlackBoxError(not_found_msg)
        raise BlackBoxHTTPError(
            f'HTTP {status}',
            request=httpx.Request('GET', str(self._client.get_httpx_client().base_url)),
            response=httpx.Response(status_code=status, content=resp.content, headers=dict(resp.headers)),
        )

    @staticmethod
    def _verify_base_url(url: str, *, ignore_ssl: bool) -> None:
        try:
            with httpx.Client(verify=not ignore_ssl) as probe:
                resp = probe.get(url)
        except httpx.ConnectError as ex:
            raise BlackBoxConnectionError(f'Failed connection to "{url}"') from ex
        except (httpx.InvalidURL, ValueError) as ex:
            raise BlackBoxInvalidUrlError(f'Check url provided "{url}"') from ex
        except httpx.HTTPError as ex:
            msg = str(ex).lower()
            if 'ssl' in msg or 'certificate' in msg:
                raise BlackBoxSSLError(
                    f'SSL verification failed for "{url}", '
                    f'it is possible to ignore SSL verification '
                    f'if you trust this server',
                ) from ex
            raise BlackBoxConnectionError(f'Failed connection to "{url}"') from ex
        if httpx.codes.is_error(resp.status_code):
            raise BlackBoxHTTPError(
                f'HTTP {resp.status_code}',
                request=resp.request,
                response=resp,
            )
