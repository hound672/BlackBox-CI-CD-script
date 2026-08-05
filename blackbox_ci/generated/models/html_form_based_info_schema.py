from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='HTMLFormBasedInfoSchema')


@_attrs_define
class HTMLFormBasedInfoSchema:
    """
    Attributes:
        form_url (str):
        form_x_path (str):
        password_field (str):
        regexp_of_success (str):
        username_field (str):
        username_value (str):
        submit_value (None | str | Unset):
        success_url (None | str | Unset):
    """

    form_url: str
    form_x_path: str
    password_field: str
    regexp_of_success: str
    username_field: str
    username_value: str
    submit_value: None | str | Unset = UNSET
    success_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        form_url = self.form_url

        form_x_path = self.form_x_path

        password_field = self.password_field

        regexp_of_success = self.regexp_of_success

        username_field = self.username_field

        username_value = self.username_value

        submit_value: None | str | Unset
        if isinstance(self.submit_value, Unset):
            submit_value = UNSET
        else:
            submit_value = self.submit_value

        success_url: None | str | Unset
        if isinstance(self.success_url, Unset):
            success_url = UNSET
        else:
            success_url = self.success_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'formUrl': form_url,
                'formXPath': form_x_path,
                'passwordField': password_field,
                'regexpOfSuccess': regexp_of_success,
                'usernameField': username_field,
                'usernameValue': username_value,
            }
        )
        if submit_value is not UNSET:
            field_dict['submitValue'] = submit_value
        if success_url is not UNSET:
            field_dict['successUrl'] = success_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        form_url = d.pop('formUrl')

        form_x_path = d.pop('formXPath')

        password_field = d.pop('passwordField')

        regexp_of_success = d.pop('regexpOfSuccess')

        username_field = d.pop('usernameField')

        username_value = d.pop('usernameValue')

        def _parse_submit_value(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        submit_value = _parse_submit_value(d.pop('submitValue', UNSET))

        def _parse_success_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        success_url = _parse_success_url(d.pop('successUrl', UNSET))

        html_form_based_info_schema = cls(
            form_url=form_url,
            form_x_path=form_x_path,
            password_field=password_field,
            regexp_of_success=regexp_of_success,
            username_field=username_field,
            username_value=username_value,
            submit_value=submit_value,
            success_url=success_url,
        )

        html_form_based_info_schema.additional_properties = d
        return html_form_based_info_schema

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
