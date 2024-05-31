from datetime import datetime
from os.path import join
from pathlib import Path
from typing import Dict, Optional, TextIO

from blackbox_ci.consts import REPORT_FILENAME_DATETIME_FORMAT
from blackbox_ci.types import (
    OnEnvUpdater,
    ReportExtension,
    ReportLocale,
    ReportTemplateShortname,
)


def generate_report_filename(
    *,
    target_name: str,
    extension: ReportExtension,
    locale: ReportLocale,
    template_shortname: ReportTemplateShortname,
) -> str:
    clean_target_name = '_'.join(
        ''.join(char if char.isalnum() else ' ' for char in target_name).strip().split()
    )
    report_template_verbose = (
        f'{template_shortname.value}_'
        if template_shortname.value != extension.value
        else ''
    )
    report_type_str = f'{report_template_verbose}{locale.value}.{extension.value}'
    cur_datetime_str = datetime.now().strftime(REPORT_FILENAME_DATETIME_FORMAT)
    report_filename = f'{cur_datetime_str}_{clean_target_name}.{report_type_str}'
    return report_filename


def save_report_content(
    *,
    report_content: bytes,
    report_dir: str,
    target_name: str,
    extension: ReportExtension,
    locale: ReportLocale,
    template_shortname: ReportTemplateShortname,
) -> str:
    report_filename = generate_report_filename(
        target_name=target_name,
        extension=extension,
        locale=locale,
        template_shortname=template_shortname,
    )
    report_full_path = join(report_dir, report_filename)
    Path(report_full_path).write_bytes(report_content)
    return report_full_path


def read_key_value_pairs(
    text_io: TextIO, on_env_updater: Optional[OnEnvUpdater] = None
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text_io:
        if line.strip():
            name, var = line.partition('=')[::2]
            result[name.strip().upper()] = var.strip()
    if on_env_updater is not None:
        on_env_updater(result)
    return result
