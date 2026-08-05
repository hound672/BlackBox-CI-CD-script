from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='BearerInfoSchema')


@_attrs_define
class BearerInfoSchema:
    """
    Attributes:
        success_url (str):
        token (str):
        success_string (None | str | Unset):
    """

    success_url: str
    token: str
    success_string: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        success_url = self.success_url

        token = self.token

        success_string: None | str | Unset
        if isinstance(self.success_string, Unset):
            success_string = UNSET
        else:
            success_string = self.success_string

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'successUrl': success_url,
                'token': token,
            }
        )
        if success_string is not UNSET:
            field_dict['successString'] = success_string

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        success_url = d.pop('successUrl')

        token = d.pop('token')

        def _parse_success_string(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        success_string = _parse_success_string(d.pop('successString', UNSET))

        bearer_info_schema = cls(
            success_url=success_url,
            token=token,
            success_string=success_string,
        )

        bearer_info_schema.additional_properties = d
        return bearer_info_schema

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
