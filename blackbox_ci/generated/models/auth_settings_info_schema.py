from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

from ..models.auth_settings_type import AuthSettingsType

T = TypeVar('T', bound='AuthSettingsInfoSchema')


@_attrs_define
class AuthSettingsInfoSchema:
    """
    Attributes:
        name (str):
        type_ (AuthSettingsType):
        uuid (str):
    """

    name: str
    type_: AuthSettingsType
    uuid: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        type_ = self.type_.value

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'name': name,
                'type': type_,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop('name')

        type_ = AuthSettingsType(d.pop('type'))

        uuid = d.pop('uuid')

        auth_settings_info_schema = cls(
            name=name,
            type_=type_,
            uuid=uuid,
        )

        auth_settings_info_schema.additional_properties = d
        return auth_settings_info_schema

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
