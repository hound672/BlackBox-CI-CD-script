from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..models.role_name_constants import RoleNameConstants
from ..types import UNSET, Unset

T = TypeVar('T', bound='UserRoleSchema')


@_attrs_define
class UserRoleSchema:
    """
    Attributes:
        uuid (UUID):
        role (None | RoleNameConstants | Unset):
    """

    uuid: UUID
    role: None | RoleNameConstants | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        uuid = str(self.uuid)

        role: None | str | Unset
        if isinstance(self.role, Unset):
            role = UNSET
        elif isinstance(self.role, RoleNameConstants):
            role = self.role.value
        else:
            role = self.role

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'uuid': uuid,
            }
        )
        if role is not UNSET:
            field_dict['role'] = role

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        uuid = UUID(d.pop('uuid'))

        def _parse_role(data: object) -> None | RoleNameConstants | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                role_type_0 = RoleNameConstants(data)

                return role_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RoleNameConstants | Unset, data)

        role = _parse_role(d.pop('role', UNSET))

        user_role_schema = cls(
            uuid=uuid,
            role=role,
        )

        user_role_schema.additional_properties = d
        return user_role_schema

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
