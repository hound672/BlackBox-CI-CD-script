import json
import logging
import sys
import time
import typing
import urllib.parse
import warnings

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

import click
import requests
import urllib3.exceptions
from requests.adapters import HTTPAdapter, Retry

# Consts
SERVER_RETRY_MAX_ATTEMPTS = 5
SERVER_RETRY_BACKOFF_FACTOR = 0.5
SERVER_RETRY_STATUSES = [502, 503, 504]

SUCCESS_EXIT_CODE = 0
ERROR_EXIT_CODE = 1
SCORE_FAIL_EXIT_CODE = 3

RESET_AUTH_PROFILE = "RESET"
RESET_API_PROFILE = "RESET"

# Types
VulnCommon = typing.Dict[str, typing.Any]


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


# Errors
class BlackBoxError(Exception):
    pass


class BlackBoxRequestError(BlackBoxError):
    pass


class BlackBoxUrlError(BlackBoxRequestError):
    pass


class BlackBoxConnectionError(BlackBoxUrlError):
    pass


class BlackBoxSSLError(BlackBoxConnectionError):
    pass


class BlackBoxInvalidUrlError(BlackBoxUrlError):
    pass


class BlackBoxHTTPError(BlackBoxRequestError):
    def __init__(
        self, *args: object, request: requests.Request, response: requests.Response
    ):
        self.request = request
        self.response = response
        super(BlackBoxHTTPError, self).__init__(*args)


class ScanResultError(Exception):
    """Report checks errors"""

    pass


class ScoreFailError(ScanResultError):
    pass


# Classes
class BlackBoxAPI:
    def __init__(self, base_url: str, api_token: str, ignore_ssl: bool) -> None:
        self._sess = requests.session()
        _retry = Retry(
            total=SERVER_RETRY_MAX_ATTEMPTS,
            status_forcelist=SERVER_RETRY_STATUSES,
            backoff_factor=SERVER_RETRY_BACKOFF_FACTOR,
            raise_on_status=False,
        )
        _adapter = HTTPAdapter(max_retries=_retry)
        self._sess.mount("http://", _adapter)
        self._sess.mount("https://", _adapter)
        self._sess.verify = not ignore_ssl
        self._test_base_url(base_url)
        self._url = urllib.parse.urljoin(base_url, "app/api/v1/")
        self._sess.hooks["response"] = [
            self._raise_for_status,
            self._ensure_json,
        ]
        self._sess.headers["Authorization"] = f"Basic {api_token}"

    def get_user_group_uuids(self) -> typing.List[str]:
        groups_url = urllib.parse.urljoin(self._url, "groups")
        resp = self._get(groups_url)
        groups = resp.json()["data"]
        return [str(group["uuid"]) for group in groups]

    def get_site_uuid(self, url: str, group_uuid: str) -> typing.Optional[str]:
        sites_url = urllib.parse.urljoin(self._url, "sites")
        resp = self._get(sites_url)
        for site in resp.json()["data"]:
            if site["url"] == url and site["group"]["uuid"] == group_uuid:
                return str(site["uuid"])
        return None

    def add_site(self, target_url: str, group_uuid: str) -> str:
        sites_url = urllib.parse.urljoin(self._url, "sites/add")
        sites_req = {"url": target_url, "groupUUID": group_uuid}
        resp = self._post(sites_url, json=sites_req)
        site_uuid = resp.json()["data"]["uuid"]
        return str(site_uuid)

    def set_site_settings(
        self,
        site_uuid: str,
        profile_uuid: str,
        authentication_uuid: typing.Optional[str],
        api_profile_uuid: typing.Optional[str],
    ) -> None:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}/settings")
        sites_req = {
            "profileUUID": profile_uuid,
            "authenticationUUID": authentication_uuid,
            "apiProfileUUID": api_profile_uuid,
        }
        self._post(sites_url, json=sites_req)

    def get_site_settings(self, site_uuid: str) -> SiteSettings:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}/settings")
        resp = self._get(sites_url)
        settings = resp.json()["data"]
        return typing.cast(SiteSettings, settings)

    def start_scan(self, site_uuid: str) -> int:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}/start")
        resp = self._post(sites_url)
        scan_id = resp.json()["data"]["id"]
        return int(scan_id)

    def stop_scan(self, site_uuid: str) -> None:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}/stop")
        self._post(sites_url)

    def is_site_busy(self, site_uuid: str) -> bool:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}")
        resp = self._get(sites_url)
        site = resp.json()["data"]
        last_scan = site["lastScan"]
        if not last_scan:
            return False
        last_scan_status = last_scan["status"]
        return last_scan_status not in ("STOPPED", "FINISHED")

    def is_scan_busy(self, site_uuid: str, scan_id: int) -> bool:
        scan_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}/scans/{scan_id}")
        resp = self._get(scan_url)
        scan = resp.json()["data"]
        return scan["status"] not in ("STOPPED", "FINISHED")

    def is_scan_ok(self, site_uuid: str, scan_id: int) -> bool:
        scan_url = urllib.parse.urljoin(self._url, f"sites/{site_uuid}/scans/{scan_id}")
        resp = self._get(scan_url)
        scan = resp.json()["data"]
        return scan["status"] == "FINISHED" and scan["errorReason"] is None

    def get_vuln_group_page(
        self,
        site_uuid: str,
        scan_id: int,
        issue_type: str,
        request_key: str,
        severity: str,
        limit: int,
        page: int,
    ) -> VulnPage:
        vuln_group_url = urllib.parse.urljoin(
            self._url,
            f"sites/{site_uuid}/scans/{scan_id}/vulnerabilities"
            f"/{issue_type}/{request_key}/{severity}"
            f"?limit={limit}&page={page}",
        )
        resp = self._get(vuln_group_url)
        return typing.cast(VulnPage, resp.json()["data"])

    def get_vuln_groups(self, site_uuid: str, scan_id: int) -> typing.List[VulnGroup]:
        vulns_url = urllib.parse.urljoin(
            self._url, f"sites/{site_uuid}/scans/{scan_id}/vulnerabilities"
        )
        resp = self._get(vulns_url)
        return typing.cast(typing.List[VulnGroup], resp.json()["data"])

    def get_score(self, site_uuid: str, scan_id: int) -> typing.Optional[float]:
        score_url = urllib.parse.urljoin(
            self._url, f"sites/{site_uuid}/scans/{scan_id}"
        )
        resp = self._get(score_url)
        score = resp.json()["data"]["score"]
        return typing.cast(typing.Optional[float], score)

    def create_shared_link(self, site_uuid: str, scan_id: int) -> str:
        url = urllib.parse.urljoin(
            self._url, f"sites/{site_uuid}/scans/{scan_id}/shared"
        )
        resp = self._post(url)
        uuid = resp.json()["data"]["uuid"]
        return typing.cast(str, uuid)

    def _request(
        self,
        method: str,
        url: str,
        **kwargs: typing.Any,
    ) -> requests.Response:
        assert method in ("GET", "POST"), f"Method {method} not allowed"

        try:
            resp = self._sess.request(method, url=url, **kwargs)
        except requests.exceptions.ConnectionError:
            raise BlackBoxConnectionError(f"Failed connection to '{url}'")
        except requests.RequestException as er:
            raise BlackBoxRequestError(f"Error while handling request {er}")
        else:
            return resp

    def _get(self, url: str, **kwargs: typing.Any) -> requests.Response:
        kwargs.setdefault("allow_redirects", True)
        return self._request("GET", url=url, **kwargs)

    def _post(
        self,
        url: str,
        **kwargs: typing.Any,
    ) -> requests.Response:
        return self._request("POST", url=url, **kwargs)

    @staticmethod
    def _raise_for_status(
        resp: requests.Response, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as er:
            raise BlackBoxHTTPError(er, request=er.request, response=er.response)

    @staticmethod
    def _ensure_json(
        resp: requests.Response, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        if resp.headers.get("content-type") != "application/json":
            raise BlackBoxError(
                "unexpected API response content type, "
                "check if BlackBox URL is specified correctly"
            )

    def _test_base_url(self, url: str) -> None:
        try:
            resp = self._sess.get(url)
        except requests.exceptions.SSLError:
            raise BlackBoxSSLError(
                f"SSL verification failed for '{url}', "
                f"it is possible to ignore SSL verification "
                f"if you trust this server"
            )
        except requests.exceptions.ConnectionError:
            raise BlackBoxConnectionError(f"Failed connection to '{url}'")
        except ValueError:
            raise BlackBoxInvalidUrlError(f"Check url provided '{url}'")
        else:
            self._raise_for_status(resp)


class BlackBoxOperator:
    _PAGE_VULNS_LIMIT = 100

    def __init__(self, url: str, api_token: str, ignore_ssl: bool) -> None:
        self._ui_base_url = url
        self._api = BlackBoxAPI(url, api_token, ignore_ssl)
        self._site_uuid: typing.Optional[str] = None
        self._scan_id: typing.Optional[int] = None
        self._group_uuid: typing.Optional[str] = None
        self._scan_finished: bool = False

    def set_user_group(self, group_uuid: typing.Optional[str]) -> None:
        group_uuid_list = self._api.get_user_group_uuids()
        if group_uuid is None and len(group_uuid_list) == 1:
            group_uuid = group_uuid_list[0]
        elif group_uuid is None:
            raise BlackBoxError(
                "the group UUID for site is required, "
                "use UI to create new group or choose existing one"
            )
        elif group_uuid not in group_uuid_list:
            raise BlackBoxError(
                "the group with the UUID specified was not found, "
                "use UI to create new or choose existing one"
            )
        self._group_uuid = group_uuid

    def set_target(self, url: str, auto_create: bool) -> None:
        assert self._group_uuid, "group not set"

        # FIXME: Search may not work because of URL normalization at the backend.
        site_uuid = self._api.get_site_uuid(url, self._group_uuid)
        if site_uuid is None:
            if not auto_create:
                raise BlackBoxError(
                    "the site with the URL specified was not found in the group, "
                    "use UI to create one manually, "
                    "or use --auto-create flag to do so automatically"
                )
            site_uuid = self._api.add_site(url, self._group_uuid)
        self._site_uuid = site_uuid

    def set_site_settings(
        self,
        profile_uuid: typing.Optional[str],
        auth_uuid: typing.Optional[str],
        api_profile_uuid: typing.Optional[str],
    ) -> None:
        assert self._site_uuid, "target not set"

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

    def ensure_target_is_idle(self, previous: str) -> None:
        assert self._site_uuid, "target not set"

        if not self._api.is_site_busy(self._site_uuid):
            return

        if previous == "fail":
            raise BlackBoxError("the target is busy")

        if previous == "stop":
            self._api.stop_scan(self._site_uuid)
        # previous is either "stop" or "wait"
        self._wait_for_target()

    def start_scan(self) -> None:
        assert self._site_uuid, "target not set"

        self._scan_id = self._api.start_scan(self._site_uuid)
        self._scan_finished = False

    def get_scan_report(self, target_url: str, share_link: bool) -> ScanReport:
        assert self._site_uuid and self._scan_id, "target or scan not set"

        report: ScanReport = {
            "target_url": target_url,
            "url": self._scan_url,
            "vulns": None,
            "score": None,
            "sharedLink": None,
        }
        if self._scan_finished:
            report["score"] = self._api.get_score(self._site_uuid, self._scan_id)
            report["vulns"] = self._collect_vulns()
        if share_link:
            report["sharedLink"] = self._create_shared_link()
        return report

    def wait_for_scan(self) -> None:
        assert self._site_uuid and self._scan_id, "target or scan not set"

        while self._api.is_scan_busy(self._site_uuid, self._scan_id):
            time.sleep(2.0)
        self._scan_finished = True
        if not self._api.is_scan_ok(self._site_uuid, self._scan_id):
            raise BlackBoxError(
                f"the scan did not succeed, "
                f"see UI for the error reason: {self._scan_url}"
            )

    def _wait_for_target(self) -> None:
        assert self._site_uuid, "target not set"

        while self._api.is_site_busy(self._site_uuid):
            time.sleep(2.0)

    def _create_shared_link(self) -> str:
        assert self._site_uuid and self._scan_id, "target or scan not set"

        shared_link_uuid = self._api.create_shared_link(self._site_uuid, self._scan_id)
        shared_link = urllib.parse.urljoin(
            self._ui_base_url, f"/shared/{shared_link_uuid}"
        )
        return shared_link

    def _collect_vulns(
        self,
    ) -> TargetVulns:
        assert self._site_uuid and self._scan_id, "target or scan not set"

        group_list = self._api.get_vuln_groups(self._site_uuid, self._scan_id)
        vuln_report: TargetVulns = {
            "issue_groups": [],
            "error_page_groups": [],
            "cve_groups": [],
        }

        for group_info in group_list:
            issue_type = group_info["issueType"]

            if issue_type == "issue":
                issue_group = self._create_group_issue(group_info)
                vuln_report["issue_groups"].append(issue_group)

            elif issue_type == "error_page":
                error_page_group = self._create_group_error_page(group_info)
                vuln_report["error_page_groups"].append(error_page_group)

            elif issue_type == "cve":
                cve_group = self._create_group_cve(group_info)
                vuln_report["cve_groups"].append(cve_group)

        return vuln_report

    def _create_group_issue(self, group_info: VulnGroup) -> GroupIssue:
        group: GroupIssue = {
            "severity": group_info["severity"],
            "category": group_info["categoryLocaleKey"],
            "group_title": group_info["groupTitle"],
            "vulns": [],
        }

        request_key = group_info["requestKey"]
        request_key = typing.cast(str, request_key)

        severity = group_info["severity"]
        count = group_info["count"]

        if count == 1:
            group["vulns"].append(self._convert_issue(group_info["vulnerability"]))
        else:
            group["vulns"].extend(
                self._read_issue_vulns(request_key=request_key, severity=severity)
            )
        return group

    def _create_group_error_page(self, group_info: VulnGroup) -> GroupErrorPage:
        group: GroupErrorPage = {
            "group_title": group_info["groupTitle"],
            "category": group_info["categoryLocaleKey"],
            "vulns": [],
        }

        request_key = group_info["requestKey"]
        request_key = typing.cast(str, request_key)

        count = group_info["count"]

        if count == 1:
            group["vulns"].append(self._convert_error_page(group_info["vulnerability"]))
        else:
            group["vulns"].extend(self._read_error_page_vulns(request_key=request_key))
        return group

    def _create_group_cve(self, group_info: VulnGroup) -> GroupCve:
        group: GroupCve = {
            "category": group_info["categoryLocaleKey"],
            "group_title": group_info["groupTitle"],
            "vulns": [],
        }

        request_key = group_info["requestKey"]
        request_key = typing.cast(str, request_key)

        count = group_info["count"]

        if count == 1:
            group["vulns"].append(self._convert_cve(group_info["vulnerability"]))
        else:
            group["vulns"].extend(self._read_cve_vulns(request_key=request_key))
        return group

    def _convert_issue(self, vuln: VulnCommon) -> VulnIssue:
        v: VulnIssue = {
            "url": vuln["urlFull"],
        }
        return v

    def _convert_error_page(self, vuln: VulnCommon) -> VulnErrorPage:
        v: VulnErrorPage = {
            "url": vuln["url"],
        }
        return v

    def _convert_cve(self, vuln: VulnCommon) -> VulnCve:
        v: VulnCve = {
            "cve_id": vuln["cveId"],
            "vector": vuln["cvssVector"],
        }
        return v

    def _read_issue_vulns(
        self, request_key: str, severity: str
    ) -> typing.List[VulnIssue]:
        vulns = self._read_all_vulns(
            issue_type="issue",
            request_key=request_key,
            severity=severity,
        )

        return [self._convert_issue(v) for v in vulns]

    def _read_error_page_vulns(self, request_key: str) -> typing.List[VulnErrorPage]:
        vulns = self._read_all_vulns(
            issue_type="error_page",
            request_key=request_key,
            severity="info",
        )

        return [self._convert_error_page(v) for v in vulns]

    def _read_cve_vulns(self, request_key: str) -> typing.List[VulnCve]:
        vulns = self._read_all_vulns(
            issue_type="cve",
            request_key=request_key,
            severity="info",
        )

        return [self._convert_cve(v) for v in vulns]

    def _read_all_vulns(
        self, *, issue_type: str, request_key: str, severity: str
    ) -> typing.List[VulnCommon]:
        """
        Just wrapper for reading all vulns
        """
        assert self._site_uuid and self._scan_id, "target or scan not set"

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
                limit=self._PAGE_VULNS_LIMIT,
                page=page,
            )
            vulns.extend(vuln_page["items"])
            has_next_page = vuln_page["hasNextPage"]
            page += 1

        return vulns

    def _get_new_profile_uuid(
        self, current_settings: SiteSettings, profile_uuid: typing.Optional[str]
    ) -> str:
        if profile_uuid is None:
            profile_uuid = current_settings["profile"]["uuid"]
        return profile_uuid

    def _get_new_auth_uuid(
        self, current_settings: SiteSettings, auth_uuid: typing.Optional[str]
    ) -> typing.Optional[str]:
        if auth_uuid is None and current_settings["authentication"] is not None:
            auth_uuid = current_settings["authentication"]["uuid"]
        elif auth_uuid == RESET_AUTH_PROFILE:
            auth_uuid = None
        return auth_uuid

    def _get_new_api_profile_uuid(
        self,
        current_settings: SiteSettings,
        api_profile_uuid: typing.Optional[str] = None,
    ) -> typing.Optional[str]:
        if api_profile_uuid is None and current_settings["apiProfile"] is not None:
            api_profile_uuid = current_settings["apiProfile"]["uuid"]
        elif api_profile_uuid == RESET_API_PROFILE:
            api_profile_uuid = None
        return api_profile_uuid

    def _is_scan_profile_changed(
        self, current_scan_profile: ScanProfile, new_profile_uuid: str
    ) -> bool:
        return current_scan_profile["uuid"] != new_profile_uuid

    def _is_auth_profile_changed(
        self,
        current_auth_profile: typing.Optional[AuthenticationProfile],
        new_auth_uuid: typing.Optional[str],
    ) -> bool:
        return (
            current_auth_profile is not None
            and new_auth_uuid != current_auth_profile["uuid"]
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
            and new_api_uuid != current_api_profile["uuid"]
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
            self._is_scan_profile_changed(current_settings["profile"], new_profile_uuid)
            or self._is_auth_profile_changed(
                current_settings["authentication"], new_auth_uuid
            )
            or self._is_api_profile_changed(
                current_settings["apiProfile"], new_api_profile_uuid
            )
        )

    @property
    def _scan_url(self) -> str:
        return urllib.parse.urljoin(
            self._ui_base_url,
            f"/sites/{self._site_uuid}/scans/{self._scan_id}",
        )


# Functions
def run_target_scan(
    blackbox_url: str,
    blackbox_api_token: str,
    target_url: str,
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
    scan_profile: typing.Optional[str],
    auth_profile: typing.Optional[str],
    api_schema: typing.Optional[str],
    group_uuid: typing.Optional[str],
) -> ScanReport:
    operator = BlackBoxOperator(blackbox_url, blackbox_api_token, ignore_ssl)
    operator.set_user_group(group_uuid)
    operator.set_target(target_url, auto_create)
    operator.ensure_target_is_idle(previous)

    if any((scan_profile, auth_profile, api_schema)):
        operator.set_site_settings(scan_profile, auth_profile, api_schema)

    operator.start_scan()
    if not no_wait:
        operator.wait_for_scan()

    return operator.get_scan_report(target_url, shared_link)


def check_errors(failed_targets: typing.List[str]) -> None:
    if failed_targets:
        failed_targets_message = "'\n'".join(failed_targets)
        raise BlackBoxError(
            f"errors occurred for targets:\n'{failed_targets_message}'\n"
            f"See error log above"
        )


def check_reports(
    reports: typing.List[ScanReport],
    fail_under_score: typing.Optional[float],
) -> None:
    if fail_under_score is not None:
        for report in reports:
            if report["score"] is not None and report["score"] < fail_under_score:
                raise ScoreFailError()


def log_current_target(target_list: typing.List[str], target: str) -> None:
    count = target_list.count(target)
    if count > 1:
        logging.warning(f"Target {target} is repeated in list {count} times")
    logging.info(f"Starting scan for target `{target}`")


def scan_target_list(
    blackbox_url: str,
    blackbox_api_token: str,
    target_list: typing.List[str],
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
    scan_profile: typing.Optional[str],
    auth_profile: typing.Optional[str],
    api_schema: typing.Optional[str],
    fail_under_score: typing.Optional[float],
    group_uuid: typing.Optional[str],
) -> None:
    reports = []
    failed_targets = []
    unique_targets = set(target_list)
    for target in unique_targets:
        log_current_target(target_list, target)
        try:
            report = run_target_scan(
                blackbox_url=blackbox_url,
                blackbox_api_token=blackbox_api_token,
                target_url=target,
                ignore_ssl=ignore_ssl,
                auto_create=auto_create,
                previous=previous,
                no_wait=no_wait,
                shared_link=shared_link,
                scan_profile=scan_profile,
                auth_profile=auth_profile,
                api_schema=api_schema,
                group_uuid=group_uuid,
            )
        except BlackBoxHTTPError as error:
            log_http_error(error)
            failed_targets.append(target)
        except BlackBoxError as error:
            logging.error(f"BlackBox error: {error}")
            failed_targets.append(target)
        else:
            reports.append(report)
            time.sleep(3.0)

    print(json.dumps(reports))
    check_errors(failed_targets)
    check_reports(reports, fail_under_score)


def scan_single_target(
    blackbox_url: str,
    blackbox_api_token: str,
    target_url: str,
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
    scan_profile: typing.Optional[str],
    auth_profile: typing.Optional[str],
    api_schema: typing.Optional[str],
    fail_under_score: typing.Optional[float],
    group_uuid: typing.Optional[str],
) -> None:
    report = run_target_scan(
        blackbox_url=blackbox_url,
        blackbox_api_token=blackbox_api_token,
        target_url=target_url,
        ignore_ssl=ignore_ssl,
        auto_create=auto_create,
        previous=previous,
        no_wait=no_wait,
        shared_link=shared_link,
        scan_profile=scan_profile,
        auth_profile=auth_profile,
        api_schema=api_schema,
        group_uuid=group_uuid,
    )
    print(json.dumps(report))

    if (
        report["score"] is not None
        and fail_under_score is not None
        and report["score"] < fail_under_score
    ):
        raise ScoreFailError()


@click.command()
@click.option(
    "--blackbox-url", envvar="BLACKBOX_URL", default="https://bbs.ptsecurity.com/"
)
@click.option("--blackbox-api-token", envvar="BLACKBOX_API_TOKEN", required=True)
@click.option(
    "--target-url",
    envvar="TARGET_URL",
    default=None,
    help="Set url of scan target.  Don't use with --target-file.",
)
@click.option(
    "--target-file",
    envvar="TARGET_FILE",
    type=click.File("r"),
    default=None,
    help="Set filename with target urls. Don't use with --target-url.",
)
@click.option(
    "--group-uuid", envvar="GROUP_UUID", help="Set group UUID for site", default=None
)
@click.option(
    "--ignore-ssl",
    envvar="IGNORE_SSL",
    is_flag=True,
    default=False,
    help="Skip verification of BlackBox API host certificate.",
)
@click.option(
    "--auto-create",
    is_flag=True,
    help="Automatically create a site if a site with the target URL "
    "in the specified group was not found.",
)
@click.option(
    "--previous",
    type=click.Choice(["wait", "stop", "fail"]),
    default="fail",
    help="What to do if the target is currently being scanned.",
)
@click.option(
    "--no-wait",
    is_flag=True,
    help="Do not wait until the started scan is finished.",
)
@click.option(
    "--shared-link",
    is_flag=True,
    default=False,
    help="Create shared link for scan.",
)
@click.option(
    "--scan-profile",
    envvar="SCAN_PROFILE",
    help="Set scan profile UUID for new scan",
)
@click.option(
    "--auth-profile",
    envvar="AUTH_PROFILE",
    help="Set authentication profile UUID for site. "
    f"For scanning without authentication specify `{RESET_AUTH_PROFILE}` in the option",
)
@click.option(
    "--api-schema",
    envvar="API_SCHEMA",
    help="Set API-schema UUID for site. "
    f"For scanning without API-schema specify `{RESET_API_PROFILE}` in the option",
)
@click.option(
    "--fail-under-score",
    type=click.FloatRange(1, 10),
    default=None,
    help="Fail with exit code 3 if report scoring is less "
    "then given score (set '1' or do not set to never fail).",
)
def main(
    blackbox_url: str,
    blackbox_api_token: str,
    target_url: str,
    target_file: typing.TextIO,
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
    scan_profile: typing.Optional[str],
    auth_profile: typing.Optional[str],
    api_schema: typing.Optional[str],
    fail_under_score: typing.Optional[float],
    group_uuid: typing.Optional[str],
) -> None:
    if ignore_ssl:
        warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

    if target_file and target_url:
        raise click.exceptions.UsageError(
            "Only one of --target-url or --target-file options allowed."
        )
    elif target_file:
        target_list = target_file.read().splitlines()
        scan_target_list(
            blackbox_url=blackbox_url,
            blackbox_api_token=blackbox_api_token,
            target_list=target_list,
            ignore_ssl=ignore_ssl,
            auto_create=auto_create,
            previous=previous,
            no_wait=no_wait,
            shared_link=shared_link,
            scan_profile=scan_profile,
            auth_profile=auth_profile,
            api_schema=api_schema,
            fail_under_score=fail_under_score,
            group_uuid=group_uuid,
        )
    elif target_url:
        scan_single_target(
            blackbox_url=blackbox_url,
            blackbox_api_token=blackbox_api_token,
            target_url=target_url,
            ignore_ssl=ignore_ssl,
            auto_create=auto_create,
            previous=previous,
            no_wait=no_wait,
            shared_link=shared_link,
            scan_profile=scan_profile,
            auth_profile=auth_profile,
            api_schema=api_schema,
            fail_under_score=fail_under_score,
            group_uuid=group_uuid,
        )
    else:
        raise click.exceptions.UsageError(
            "One of --target-url or --target-file options required."
        )


def log_http_error(err: BlackBoxHTTPError) -> None:
    verbose = ""
    if isinstance(err.response, requests.Response):
        if err.response.headers["Content-Type"] == "application/json":
            body_json = err.response.json()
            verbose = json.dumps(body_json, indent=2)
            verbose = f"\n{verbose}"
    logging.error(f"BlackBox API call failed: {err}{verbose}")


if __name__ == "__main__":  # noqa: C901
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    try:
        main()
    except BlackBoxHTTPError as err:
        log_http_error(err)
    except BlackBoxUrlError as err:
        logging.error(f"Invalid BlackBox url or server connection failed: {err}")
    except BlackBoxError as err:
        logging.error(f"BlackBox error: {err}")
    except ScoreFailError:
        sys.exit(SCORE_FAIL_EXIT_CODE)
    else:
        sys.exit(SUCCESS_EXIT_CODE)
    sys.exit(ERROR_EXIT_CODE)
