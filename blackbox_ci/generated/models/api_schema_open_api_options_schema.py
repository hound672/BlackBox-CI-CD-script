from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='APISchemaOpenAPIOptionsSchema')


@_attrs_define
class APISchemaOpenAPIOptionsSchema:
    """
    Attributes:
        prefix (str | Unset):  Default: ''.
    """

    prefix: str | Unset = ''
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        prefix = self.prefix

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if prefix is not UNSET:
            field_dict['prefix'] = prefix

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        prefix = d.pop('prefix', UNSET)

        api_schema_open_api_options_schema = cls(
            prefix=prefix,
        )

        api_schema_open_api_options_schema.additional_properties = d
        return api_schema_open_api_options_schema

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
