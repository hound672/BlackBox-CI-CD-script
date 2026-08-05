from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='AuthProfilesConflicts')


@_attrs_define
class AuthProfilesConflicts:
    """
    Attributes:
        auth_chains (list[str]):
        sites (list[str]):
    """

    auth_chains: list[str]
    sites: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        auth_chains = self.auth_chains

        sites = self.sites

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'authChains': auth_chains,
                'sites': sites,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        auth_chains = cast(list[str], d.pop('authChains'))

        sites = cast(list[str], d.pop('sites'))

        auth_profiles_conflicts = cls(
            auth_chains=auth_chains,
            sites=sites,
        )

        auth_profiles_conflicts.additional_properties = d
        return auth_profiles_conflicts

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
