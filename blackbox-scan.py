import json
import logging
import sys
import time
import typing
import urllib.parse
import warnings
from enum import Enum, EnumMeta

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

import click
import requests
import urllib3.exceptions

# Consts
SUCCESS_EXIT_CODE = 0
ERROR_EXIT_CODE = 1
SCORE_FAIL_EXIT_CODE = 3

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
    url: str
    vulns: typing.Optional[TargetVulns]
    sharedLink: typing.Optional[str]
    score: typing.Optional["Score"]


# Errors
class BlackBoxError(Exception):
    pass


class ScanResultError(Exception):
    """Report checks errors"""

    pass


class ScoreFailError(ScanResultError):
    pass


# Classes
class Score(Enum):
    A_plus = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"

    def __lt__(self, other: "Score") -> bool:
        members = list(Score)
        self_index = members.index(self)
        other_index = members.index(other)
        return self_index > other_index


class ScoreChoice(click.Choice):
    def __init__(
        self, enum: EnumMeta, case_sensitive: bool = False, use_value: bool = False
    ):
        self.enum = enum
        self.use_value = use_value
        choices: typing.List[str] = [
            str(e.value) if use_value else e.name
            for e in typing.cast(typing.List[Enum], self.enum)
        ]
        super().__init__(choices=choices, case_sensitive=case_sensitive)

    def convert(
        self,
        value: typing.Any,
        param: typing.Optional["click.Parameter"],
        ctx: typing.Optional["click.Context"],
    ) -> Enum:
        value = super().convert(value, param, ctx)
        if self.use_value:
            return next(
                e
                for e in typing.cast(typing.List[Enum], self.enum)
                if str(e.value) == value
            )
        return self.enum[value]


class BlackBoxAPI:
    def __init__(self, url: str, api_token: str, ignore_ssl: bool) -> None:
        self._url = url
        self._sess = requests.session()
        self._sess.verify = not ignore_ssl
        self._sess.hooks["response"] = [
            self._raise_for_status,
            self._ensure_json,
        ]
        self._sess.headers["Authorization"] = f"Basic {api_token}"

    def get_site_id(self, url: str) -> typing.Optional[int]:
        sites_url = urllib.parse.urljoin(self._url, "sites")
        resp = self._sess.get(sites_url)
        for site in resp.json()["data"]:
            if site["url"] == url:
                return int(site["id"])
        return None

    def add_site(self, target_url: str) -> int:
        sites_url = urllib.parse.urljoin(self._url, "sites/add")
        sites_req = {"url": target_url}
        resp = self._sess.post(sites_url, json=sites_req)
        site_id = resp.json()["data"]["id"]
        return int(site_id)

    def set_site_profile_uuid(self, site_id: int, profile_uuid: str) -> None:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/settings")
        sites_req = {"profileUUID": profile_uuid}
        self._sess.post(sites_url, json=sites_req)

    def get_site_profile_uuid(self, site_id: int) -> str:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/settings")
        resp = self._sess.get(sites_url)
        return str(resp.json()["data"]["profile"]["uuid"])

    def start_scan(self, site_id: int) -> int:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/start")
        resp = self._sess.post(sites_url)
        scan_id = resp.json()["data"]["id"]
        return int(scan_id)

    def stop_scan(self, site_id: int) -> None:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/stop")
        self._sess.post(sites_url)

    def is_site_busy(self, site_id: int) -> bool:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}")
        resp = self._sess.get(sites_url)
        site = resp.json()["data"]
        last_scan = site["lastScan"]
        if not last_scan:
            return False
        last_scan_status = last_scan["status"]
        return last_scan_status not in ("STOPPED", "FINISHED")

    def is_scan_busy(self, site_id: int, scan_id: int) -> bool:
        scan_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}")
        resp = self._sess.get(scan_url)
        scan = resp.json()["data"]
        return scan["status"] not in ("STOPPED", "FINISHED")

    def is_scan_ok(self, site_id: int, scan_id: int) -> bool:
        scan_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}")
        resp = self._sess.get(scan_url)
        scan = resp.json()["data"]
        return scan["status"] == "FINISHED" and scan["errorReason"] is None

    def get_group_page(
        self,
        site_id: int,
        scan_id: int,
        issue_type: str,
        request_key: str,
        severity: str,
        limit: int,
        page: int,
    ) -> VulnPage:
        vuln_group_url = urllib.parse.urljoin(
            self._url,
            f"sites/{site_id}/scans/{scan_id}/vulnerabilities"
            f"/{issue_type}/{request_key}/{severity}"
            f"?limit={limit}&page={page}",
        )
        resp = self._sess.get(vuln_group_url)
        return typing.cast(VulnPage, resp.json()["data"])

    def get_groups(self, site_id: int, scan_id: int) -> typing.List[VulnGroup]:
        vulns_url = urllib.parse.urljoin(
            self._url, f"sites/{site_id}/scans/{scan_id}/vulnerabilities"
        )
        resp = self._sess.get(vulns_url)
        return typing.cast(typing.List[VulnGroup], resp.json()["data"])

    def get_score(self, site_id: int, scan_id: int) -> typing.Optional[Score]:
        score_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}")
        resp = self._sess.get(score_url)
        score = resp.json()["data"]["score"]
        score = Score[score] if score is not None else None
        return typing.cast(typing.Optional[Score], score)

    def create_shared_link(self, site_id: int, scan_id: int) -> str:
        url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}/shared")
        resp = self._sess.post(url)
        uuid = resp.json()["data"]["uuid"]
        return typing.cast(str, uuid)

    @staticmethod
    def _raise_for_status(
        resp: requests.Response, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        resp.raise_for_status()

    @staticmethod
    def _ensure_json(
        resp: requests.Response, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        if resp.headers.get("content-type") != "application/json":
            raise BlackBoxError(
                "unexpected API response content type, "
                "check if BlackBox URL is specified correctly"
            )


class BlackBoxOperator:
    _PAGE_VULNS_LIMIT = 100

    def __init__(self, url: str, api_token: str, ignore_ssl: bool) -> None:
        self._ui_base_url = url
        api_url = urllib.parse.urljoin(url, "app/api/v1/")
        self._api = BlackBoxAPI(api_url, api_token, ignore_ssl)
        self._site_id: typing.Optional[int] = None
        self._scan_id: typing.Optional[int] = None
        self._scan_finished: bool = False

    def set_target(self, url: str, auto_create: bool) -> None:
        # FIXME: Search may not work because of URL normalization at the backend.
        site_id = self._api.get_site_id(url)
        if site_id is None:
            if not auto_create:
                raise BlackBoxError(
                    "the site with the URL specified was not found, "
                    "use UI to create one manually, "
                    "or use --auto-create flag to do so automatically"
                )
            site_id = self._api.add_site(url)
        self._site_id = site_id

    def set_site_profile(self, profile_uuid: str) -> None:
        assert self._site_id, "target not set"

        current_uuid = self._api.get_site_profile_uuid(self._site_id)
        if current_uuid != profile_uuid:
            self._api.set_site_profile_uuid(self._site_id, profile_uuid)

    def ensure_target_is_idle(self, previous: str) -> None:
        assert self._site_id, "target not set"

        if not self._api.is_site_busy(self._site_id):
            return

        if previous == "fail":
            raise BlackBoxError("the target is busy")

        if previous == "stop":
            self._api.stop_scan(self._site_id)
        # previous is either "stop" or "wait"
        self._wait_for_target()

    def start_scan(self) -> None:
        assert self._site_id, "target not set"

        self._scan_id = self._api.start_scan(self._site_id)
        self._scan_finished = False

    def get_scan_report(self, share_link: bool) -> ScanReport:
        assert self._site_id and self._scan_id, "target or scan not set"

        report: ScanReport = {
            "url": self._scan_url,
            "vulns": None,
            "score": None,
            "sharedLink": None,
        }
        if self._scan_finished:
            report["score"] = self._api.get_score(self._site_id, self._scan_id)
            report["vulns"] = self._collect_vulns()
        if share_link:
            report["sharedLink"] = self._create_shared_link()
        return report

    def wait_for_scan(self) -> None:
        assert self._site_id and self._scan_id, "target or scan not set"

        while self._api.is_scan_busy(self._site_id, self._scan_id):
            time.sleep(2.0)
        self._scan_finished = True
        if not self._api.is_scan_ok(self._site_id, self._scan_id):
            raise BlackBoxError(
                f"the scan did not succeed, "
                f"see UI for the error reason: {self._scan_url}"
            )

    def _wait_for_target(self) -> None:
        assert self._site_id, "target not set"

        while self._api.is_site_busy(self._site_id):
            time.sleep(2.0)

    def _create_shared_link(self) -> str:
        assert self._site_id and self._scan_id, "target or scan not set"

        shared_link_uuid = self._api.create_shared_link(self._site_id, self._scan_id)
        shared_link = urllib.parse.urljoin(
            self._ui_base_url, f"/shared/{shared_link_uuid}"
        )
        return shared_link

    def _collect_vulns(
        self,
    ) -> TargetVulns:
        assert self._site_id and self._scan_id, "target or scan not set"

        group_list = self._api.get_groups(self._site_id, self._scan_id)
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
        assert self._site_id and self._scan_id, "target or scan not set"

        vulns: typing.List[VulnCommon] = []
        has_next_page = True
        page = 1  # page starts with 1
        while has_next_page is True:
            vuln_page = self._api.get_group_page(
                self._site_id,
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

    @property
    def _scan_url(self) -> str:
        return urllib.parse.urljoin(
            self._ui_base_url,
            f"/sites/{self._site_id}/scans/{self._scan_id}",
        )


# Functions
def report_serializer(x: typing.Any) -> typing.Any:
    if isinstance(x, Score):
        return x.value
    return x


@click.command()
@click.option(
    "--blackbox-url", envvar="BLACKBOX_URL", default="https://bbs.ptsecurity.com/"
)
@click.option("--blackbox-api-token", envvar="BLACKBOX_API_TOKEN", required=True)
@click.option("--target-url", envvar="TARGET_URL", required=True)
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
    help="Automatically create a site if a site with the target URL was not found.",
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
    "--fail-under-score",
    type=ScoreChoice(Score, use_value=True),
    default=None,
    help="Fail with exit code 3 if report scoring is less "
    "then given score (set 'F' or do not set to never fail).",
)
def main(
    blackbox_url: str,
    blackbox_api_token: str,
    target_url: str,
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
    scan_profile: typing.Optional[str],
    fail_under_score: typing.Optional[Score],
) -> None:
    if ignore_ssl:
        warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

    operator = BlackBoxOperator(blackbox_url, blackbox_api_token, ignore_ssl)
    operator.set_target(target_url, auto_create)
    operator.ensure_target_is_idle(previous)

    if scan_profile:
        operator.set_site_profile(scan_profile)

    operator.start_scan()
    if not no_wait:
        operator.wait_for_scan()

    report = operator.get_scan_report(shared_link)
    print(json.dumps(report, default=report_serializer))

    if (
        report["score"] is not None
        and fail_under_score is not None
        and report["score"] < fail_under_score
    ):
        raise ScoreFailError()


def log_http_error(err: requests.HTTPError) -> None:
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
    except requests.HTTPError as err:
        log_http_error(err)
    except BlackBoxError as err:
        logging.error(f"BlackBox error: {err}")
    except ScoreFailError:
        sys.exit(SCORE_FAIL_EXIT_CODE)
    else:
        sys.exit(SUCCESS_EXIT_CODE)
    sys.exit(ERROR_EXIT_CODE)
