from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

from ..models.group_type import GroupType
from ..models.role_name_constants import RoleNameConstants
from ..types import UNSET, Unset

T = TypeVar('T', bound='GroupRoleFullInfoSchema')


@_attrs_define
class GroupRoleFullInfoSchema:
    """
    Attributes:
        created_at (datetime.datetime):
        name (str):
        type_ (GroupType):
        uuid (str):
        role (None | RoleNameConstants | Unset):
    """

    created_at: datetime.datetime
    name: str
    type_: GroupType
    uuid: str
    role: None | RoleNameConstants | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at.isoformat()

        name = self.name

        type_ = self.type_.value

        uuid = self.uuid

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
                'createdAt': created_at,
                'name': name,
                'type': type_,
                'uuid': uuid,
            }
        )
        if role is not UNSET:
            field_dict['role'] = role

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        created_at = isoparse(d.pop('createdAt'))

        name = d.pop('name')

        type_ = GroupType(d.pop('type'))

        uuid = d.pop('uuid')

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

        group_role_full_info_schema = cls(
            created_at=created_at,
            name=name,
            type_=type_,
            uuid=uuid,
            role=role,
        )

        group_role_full_info_schema.additional_properties = d
        return group_role_full_info_schema

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
