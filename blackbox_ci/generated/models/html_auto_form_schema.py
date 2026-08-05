from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='HTMLAutoFormSchema')


@_attrs_define
class HTMLAutoFormSchema:
    """
    Attributes:
        form_url (str):
        password (str):
        success_string (str):
        username (str):
        success_url (None | str | Unset):
    """

    form_url: str
    password: str
    success_string: str
    username: str
    success_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        form_url = self.form_url

        password = self.password

        success_string = self.success_string

        username = self.username

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
                'password': password,
                'successString': success_string,
                'username': username,
            }
        )
        if success_url is not UNSET:
            field_dict['successUrl'] = success_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        form_url = d.pop('formUrl')

        password = d.pop('password')

        success_string = d.pop('successString')

        username = d.pop('username')

        def _parse_success_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        success_url = _parse_success_url(d.pop('successUrl', UNSET))

        html_auto_form_schema = cls(
            form_url=form_url,
            password=password,
            success_string=success_string,
            username=username,
            success_url=success_url,
        )

        html_auto_form_schema.additional_properties = d
        return html_auto_form_schema

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
