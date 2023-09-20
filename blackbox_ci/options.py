import typing
from enum import Enum, EnumMeta

import click

from blackbox_ci.consts import (
    NO_WAIT_OPTION,
    REPORT_DIR_OPTION,
    TARGET_FILE_OPTION,
    TARGET_URL_OPTION,
)


class EnumChoice(click.Choice):
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
        param: typing.Optional['click.Parameter'],
        ctx: typing.Optional['click.Context'],
    ) -> Enum:
        value = super().convert(value, param, ctx)
        if self.use_value:
            return next(
                e
                for e in typing.cast(typing.List[Enum], self.enum)
                if str(e.value) == value
            )
        return self.enum[value]


def check_target_source(
    *,
    target_url: str,
    target_file: typing.TextIO,
) -> None:
    if target_file and target_url:
        raise click.exceptions.UsageError(
            f'Only one of {TARGET_URL_OPTION} or {TARGET_FILE_OPTION} options allowed.'
        )
    elif not target_file and not target_url:
        raise click.exceptions.UsageError(
            f'One of {TARGET_URL_OPTION} or {TARGET_FILE_OPTION} options required.'
        )


def check_report_output_options(
    *,
    report_dir: typing.Optional[str],
    no_wait: bool,
) -> None:
    if no_wait and report_dir:
        raise click.exceptions.UsageError(
            f'{REPORT_DIR_OPTION} option cannot be used with {NO_WAIT_OPTION} option. '
            'To generate a report the scan must be finished or stopped.'
        )
