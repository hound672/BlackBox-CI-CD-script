from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='RawCookieInfoSchema')


@_attrs_define
class RawCookieInfoSchema:
    """
    Attributes:
        cookies (list[str]):
        regexp_of_success (str):
        success_url (str):
    """

    cookies: list[str]
    regexp_of_success: str
    success_url: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cookies = self.cookies

        regexp_of_success = self.regexp_of_success

        success_url = self.success_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'cookies': cookies,
                'regexpOfSuccess': regexp_of_success,
                'successUrl': success_url,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cookies = cast(list[str], d.pop('cookies'))

        regexp_of_success = d.pop('regexpOfSuccess')

        success_url = d.pop('successUrl')

        raw_cookie_info_schema = cls(
            cookies=cookies,
            regexp_of_success=regexp_of_success,
            success_url=success_url,
        )

        raw_cookie_info_schema.additional_properties = d
        return raw_cookie_info_schema

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
