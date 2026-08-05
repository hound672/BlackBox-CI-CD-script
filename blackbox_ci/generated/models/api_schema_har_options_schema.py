from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='APISchemaHAROptionsSchema')


@_attrs_define
class APISchemaHAROptionsSchema:
    """
    Attributes:
        cookie_blacklist (list[str] | Unset):
        header_blacklist (list[str] | Unset):
    """

    cookie_blacklist: list[str] | Unset = UNSET
    header_blacklist: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cookie_blacklist: list[str] | Unset = UNSET
        if not isinstance(self.cookie_blacklist, Unset):
            cookie_blacklist = self.cookie_blacklist

        header_blacklist: list[str] | Unset = UNSET
        if not isinstance(self.header_blacklist, Unset):
            header_blacklist = self.header_blacklist

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cookie_blacklist is not UNSET:
            field_dict['cookieBlacklist'] = cookie_blacklist
        if header_blacklist is not UNSET:
            field_dict['headerBlacklist'] = header_blacklist

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cookie_blacklist = cast(list[str], d.pop('cookieBlacklist', UNSET))

        header_blacklist = cast(list[str], d.pop('headerBlacklist', UNSET))

        api_schema_har_options_schema = cls(
            cookie_blacklist=cookie_blacklist,
            header_blacklist=header_blacklist,
        )

        api_schema_har_options_schema.additional_properties = d
        return api_schema_har_options_schema

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
