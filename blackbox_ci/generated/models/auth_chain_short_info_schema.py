from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.group_short_info_schema import GroupShortInfoSchema


T = TypeVar('T', bound='AuthChainShortInfoSchema')


@_attrs_define
class AuthChainShortInfoSchema:
    """
    Attributes:
        group (GroupShortInfoSchema):
        name (str):
        uuid (UUID):
    """

    group: GroupShortInfoSchema
    name: str
    uuid: UUID
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group = self.group.to_dict()

        name = self.name

        uuid = str(self.uuid)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'group': group,
                'name': name,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_short_info_schema import GroupShortInfoSchema

        d = dict(src_dict)
        group = GroupShortInfoSchema.from_dict(d.pop('group'))

        name = d.pop('name')

        uuid = UUID(d.pop('uuid'))

        auth_chain_short_info_schema = cls(
            group=group,
            name=name,
            uuid=uuid,
        )

        auth_chain_short_info_schema.additional_properties = d
        return auth_chain_short_info_schema

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
