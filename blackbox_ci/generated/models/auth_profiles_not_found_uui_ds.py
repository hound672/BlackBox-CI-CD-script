from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='AuthProfilesNotFoundUUIDs')


@_attrs_define
class AuthProfilesNotFoundUUIDs:
    """
    Attributes:
        uui_ds (list[str]):
    """

    uui_ds: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        uui_ds = self.uui_ds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'UUIDs': uui_ds,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        uui_ds = cast(list[str], d.pop('UUIDs'))

        auth_profiles_not_found_uui_ds = cls(
            uui_ds=uui_ds,
        )

        auth_profiles_not_found_uui_ds.additional_properties = d
        return auth_profiles_not_found_uui_ds

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
