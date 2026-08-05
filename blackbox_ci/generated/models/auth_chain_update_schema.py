from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='AuthChainUpdateSchema')


@_attrs_define
class AuthChainUpdateSchema:
    """
    Attributes:
        name (None | str | Unset):
        profiles (list[UUID] | None | Unset):
    """

    name: None | str | Unset = UNSET
    profiles: list[UUID] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        profiles: list[str] | None | Unset
        if isinstance(self.profiles, Unset):
            profiles = UNSET
        elif isinstance(self.profiles, list):
            profiles = []
            for profiles_type_0_item_data in self.profiles:
                profiles_type_0_item = str(profiles_type_0_item_data)
                profiles.append(profiles_type_0_item)

        else:
            profiles = self.profiles

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict['name'] = name
        if profiles is not UNSET:
            field_dict['profiles'] = profiles

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop('name', UNSET))

        def _parse_profiles(data: object) -> list[UUID] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                profiles_type_0 = []
                _profiles_type_0 = data
                for profiles_type_0_item_data in _profiles_type_0:
                    profiles_type_0_item = UUID(profiles_type_0_item_data)

                    profiles_type_0.append(profiles_type_0_item)

                return profiles_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[UUID] | None | Unset, data)

        profiles = _parse_profiles(d.pop('profiles', UNSET))

        auth_chain_update_schema = cls(
            name=name,
            profiles=profiles,
        )

        auth_chain_update_schema.additional_properties = d
        return auth_chain_update_schema

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
