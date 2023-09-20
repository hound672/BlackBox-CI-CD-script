import json
import logging
import sys
import time
import typing
import warnings

import click
import requests
import urllib3.exceptions
from requests.adapters import HTTPAdapter, Retry

from blackbox_ci.blackbox_api import BlackBoxAPI
from blackbox_ci.blackbox_operator import BlackBoxOperator
from blackbox_ci.consts import (
    API_SCHEMA_ENV,
    API_SCHEMA_OPTION,
    AUTH_PROFILE_ENV,
    AUTH_PROFILE_OPTION,
    AUTO_CREATE_OPTION,
    BLACKBOX_API_TOKEN_ENV,
    BLACKBOX_API_TOKEN_OPTION,
    BLACKBOX_URL_ENV,
    BLACKBOX_URL_OPTION,
    ERROR_EXIT_CODE,
    FAIL_UNDER_SCORE_OPTION,
    GROUP_UUID_ENV,
    GROUP_UUID_OPTION,
    IGNORE_SSL_ENV,
    IGNORE_SSL_OPTION,
    NO_WAIT_OPTION,
    PREVIOUS_OPTION,
    REPORT_DIR_OPTION,
    REPORT_LOCALE_OPTION,
    REPORT_TEMPLATE_OPTION,
    RESET_API_PROFILE,
    RESET_AUTH_PROFILE,
    SCAN_PROFILE_ENV,
    SCAN_PROFILE_OPTION,
    SCORE_FAIL_EXIT_CODE,
    SERVER_RETRY_BACKOFF_FACTOR,
    SERVER_RETRY_MAX_ATTEMPTS,
    SERVER_RETRY_STATUSES,
    SHARED_LINK_OPTION,
    SUCCESS_EXIT_CODE,
    TARGET_FILE_ENV,
    TARGET_FILE_OPTION,
    TARGET_URL_ENV,
    TARGET_URL_OPTION,
)
from blackbox_ci.errors import (
    BlackBoxError,
    BlackBoxHTTPError,
    BlackBoxUrlError,
    ScoreFailError,
)
from blackbox_ci.options import (
    EnumChoice,
    check_report_output_options,
    check_target_source,
)
from blackbox_ci.types import ReportLocale, ReportTemplateShortname, ScanReport


def run_target_scan(
    *,
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
    report_dir: typing.Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
) -> ScanReport:
    retry = Retry(
        total=SERVER_RETRY_MAX_ATTEMPTS,
        status_forcelist=SERVER_RETRY_STATUSES,
        backoff_factor=SERVER_RETRY_BACKOFF_FACTOR,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    api = BlackBoxAPI(blackbox_url, blackbox_api_token, ignore_ssl, adapter=adapter)
    operator = BlackBoxOperator(blackbox_url, api=api)

    operator.set_user_group(group_uuid)
    operator.set_target(target_url, auto_create)
    operator.ensure_target_is_idle(previous)

    if any((scan_profile, auth_profile, api_schema)):
        operator.set_site_settings(scan_profile, auth_profile, api_schema)

    operator.start_scan()
    report_path = None
    if not no_wait:
        operator.wait_for_scan()
        if report_dir is not None:
            report_path = operator.generate_report_file(
                locale=report_locale,
                template_shortname=report_template,
                output_dir=report_dir,
            )
    return operator.get_scan_report(target_url, shared_link, report_path)


def check_errors(failed_targets: typing.List[str]) -> None:
    if failed_targets:
        failed_targets_message = '"\n"'.join(failed_targets)
        raise BlackBoxError(
            f'errors occurred for targets:\n"{failed_targets_message}"\n'
            f'See error log above'
        )


def check_reports(
    reports: typing.List[ScanReport],
    fail_under_score: typing.Optional[float],
) -> None:
    if fail_under_score is not None:
        for report in reports:
            if report['score'] is not None and report['score'] < fail_under_score:
                raise ScoreFailError()


def log_current_target(target_list: typing.List[str], target: str) -> None:
    count = target_list.count(target)
    if count > 1:
        logging.warning(f'Target {target} is repeated in list {count} times')
    logging.info(f'Starting scan for target `{target}`')


def log_http_error(err: BlackBoxHTTPError) -> None:
    verbose = ''
    if isinstance(err.response, requests.Response):
        if err.response.headers['Content-Type'] == 'application/json':
            body_json = err.response.json()
            verbose = json.dumps(body_json, indent=2)
            verbose = f'\n{verbose}'
    logging.error(f'BlackBox API call failed: {err}{verbose}')


def scan_target_list(
    *,
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
    report_dir: typing.Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
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
                report_dir=report_dir,
                report_template=report_template,
                report_locale=report_locale,
            )
        except BlackBoxHTTPError as error:
            log_http_error(error)
            failed_targets.append(target)
        except BlackBoxError as error:
            logging.error(f'BlackBox error: {error}')
            failed_targets.append(target)
        else:
            reports.append(report)
            time.sleep(3.0)

    print(json.dumps(reports))
    check_errors(failed_targets)
    check_reports(reports, fail_under_score)


def scan_single_target(
    *,
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
    report_dir: typing.Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
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
        report_dir=report_dir,
        report_template=report_template,
        report_locale=report_locale,
    )
    print(json.dumps(report))

    if (
        report['score'] is not None
        and fail_under_score is not None
        and report['score'] < fail_under_score
    ):
        raise ScoreFailError()


@click.command()
@click.option(
    BLACKBOX_URL_OPTION, envvar=BLACKBOX_URL_ENV, default='https://bbs.ptsecurity.com/'
)
@click.option(BLACKBOX_API_TOKEN_OPTION, envvar=BLACKBOX_API_TOKEN_ENV, required=True)
@click.option(
    TARGET_URL_OPTION,
    envvar=TARGET_URL_ENV,
    default=None,
    help=f'Set url of scan target. Do not use with {TARGET_FILE_OPTION}.',
)
@click.option(
    TARGET_FILE_OPTION,
    envvar=TARGET_FILE_ENV,
    type=click.File('r'),
    default=None,
    help=f'Set filename with target urls. Do not use with {TARGET_URL_OPTION}.',
)
@click.option(
    GROUP_UUID_OPTION,
    envvar=GROUP_UUID_ENV,
    help='Set group UUID for site',
    default=None,
)
@click.option(
    IGNORE_SSL_OPTION,
    envvar=IGNORE_SSL_ENV,
    is_flag=True,
    default=False,
    help='Skip verification of BlackBox API host certificate.',
)
@click.option(
    AUTO_CREATE_OPTION,
    is_flag=True,
    help='Automatically create a site if a site with the target URL '
    'in the specified group was not found.',
)
@click.option(
    PREVIOUS_OPTION,
    type=click.Choice(['wait', 'stop', 'fail']),
    default='fail',
    help='What to do if the target is currently being scanned.',
)
@click.option(
    NO_WAIT_OPTION,
    is_flag=True,
    help='Do not wait until the started scan is finished.',
)
@click.option(
    SHARED_LINK_OPTION,
    is_flag=True,
    default=False,
    help='Create shared link for scan.',
)
@click.option(
    SCAN_PROFILE_OPTION,
    envvar=SCAN_PROFILE_ENV,
    help='Set scan profile UUID for new scan',
)
@click.option(
    AUTH_PROFILE_OPTION,
    envvar=AUTH_PROFILE_ENV,
    help='Set authentication profile UUID for site. '
    f'For scanning without authentication specify `{RESET_AUTH_PROFILE}` in the option',
)
@click.option(
    API_SCHEMA_OPTION,
    envvar=API_SCHEMA_ENV,
    help='Set API-schema UUID for site. '
    f'For scanning without API-schema specify `{RESET_API_PROFILE}` in the option',
)
@click.option(
    FAIL_UNDER_SCORE_OPTION,
    type=click.FloatRange(1, 10),
    default=None,
    help='Fail with exit code 3 if report scoring is less '
    'than given score (set "1" or do not set to never fail).',
)
@click.option(
    REPORT_DIR_OPTION,
    type=click.Path(
        exists=True, resolve_path=True, file_okay=False, dir_okay=True, writable=True
    ),
    default=None,
    help='Set directory path for storing the generated report file. '
    'If the option is used, the report will be saved in the specified directory. '
    f'Cannot be used with {NO_WAIT_OPTION} option. '
    'To generate a report the scan must be finished or stopped.',
)
@click.option(
    REPORT_TEMPLATE_OPTION,
    type=EnumChoice(ReportTemplateShortname, case_sensitive=False, use_value=True),
    default=ReportTemplateShortname.HTML,
    help='Template shortname of the report to be generated. '
    f'Specifies file format for report in {REPORT_DIR_OPTION}.',
)
@click.option(
    REPORT_LOCALE_OPTION,
    type=EnumChoice(ReportLocale, case_sensitive=False, use_value=True),
    default=ReportLocale.RU,
    help='Localization of the report file to be generated. '
    f'Specifies file localization for report in {REPORT_DIR_OPTION}.',
)
def run_command(
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
    report_dir: typing.Optional[str],
    report_template: ReportTemplateShortname,
    report_locale: ReportLocale,
) -> None:
    check_target_source(target_url=target_url, target_file=target_file)
    check_report_output_options(report_dir=report_dir, no_wait=no_wait)

    if ignore_ssl:
        warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)

    if target_file:
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
            report_dir=report_dir,
            report_template=report_template,
            report_locale=report_locale,
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
            report_dir=report_dir,
            report_template=report_template,
            report_locale=report_locale,
        )


def main() -> None:  # noqa: C901
    logging.basicConfig(
        level=logging.DEBUG, format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )
    try:
        run_command()
    except BlackBoxHTTPError as err:
        log_http_error(err)
    except BlackBoxUrlError as err:
        logging.error(f'Invalid BlackBox url or server connection failed: {err}')
    except BlackBoxError as err:
        logging.error(f'BlackBox error: {err}')
    except ScoreFailError:
        sys.exit(SCORE_FAIL_EXIT_CODE)
    else:
        sys.exit(SUCCESS_EXIT_CODE)
    sys.exit(ERROR_EXIT_CODE)
