from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

from ..models.role_name_constants import RoleNameConstants

T = TypeVar('T', bound='RolesListSchema')


@_attrs_define
class RolesListSchema:
    """
    Attributes:
        roles (list[RoleNameConstants]):
    """

    roles: list[RoleNameConstants]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        roles = []
        for roles_item_data in self.roles:
            roles_item = roles_item_data.value
            roles.append(roles_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'roles': roles,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        roles = []
        _roles = d.pop('roles')
        for roles_item_data in _roles:
            roles_item = RoleNameConstants(roles_item_data)

            roles.append(roles_item)

        roles_list_schema = cls(
            roles=roles,
        )

        roles_list_schema.additional_properties = d
        return roles_list_schema

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
