from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.role_name_constants import RoleNameConstants

T = TypeVar('T', bound='GroupRolePermissionsSchema')


@_attrs_define
class GroupRolePermissionsSchema:
    """
    Attributes:
        name (None | RoleNameConstants):
        permissions (list[str]):
    """

    name: None | RoleNameConstants
    permissions: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str
        if isinstance(self.name, RoleNameConstants):
            name = self.name.value
        else:
            name = self.name

        permissions = self.permissions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'name': name,
                'permissions': permissions,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_name(data: object) -> None | RoleNameConstants:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                name_type_0 = RoleNameConstants(data)

                return name_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RoleNameConstants, data)

        name = _parse_name(d.pop('name'))

        permissions = cast(list[str], d.pop('permissions'))

        group_role_permissions_schema = cls(
            name=name,
            permissions=permissions,
        )

        group_role_permissions_schema.additional_properties = d
        return group_role_permissions_schema

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
