from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.profile_type import ProfileType

if TYPE_CHECKING:
    from ..models.group_short_info_schema import GroupShortInfoSchema


T = TypeVar('T', bound='ProfileShortInfoSchema')


@_attrs_define
class ProfileShortInfoSchema:
    """
    Attributes:
        group (GroupShortInfoSchema | None):
        is_deleted (bool):
        name (str):
        type_ (ProfileType):
        uuid (str):
    """

    group: GroupShortInfoSchema | None
    is_deleted: bool
    name: str
    type_: ProfileType
    uuid: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.group_short_info_schema import GroupShortInfoSchema

        group: dict[str, Any] | None
        if isinstance(self.group, GroupShortInfoSchema):
            group = self.group.to_dict()
        else:
            group = self.group

        is_deleted = self.is_deleted

        name = self.name

        type_ = self.type_.value

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'group': group,
                'isDeleted': is_deleted,
                'name': name,
                'type': type_,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_short_info_schema import GroupShortInfoSchema

        d = dict(src_dict)

        def _parse_group(data: object) -> GroupShortInfoSchema | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                group_type_0 = GroupShortInfoSchema.from_dict(data)

                return group_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GroupShortInfoSchema | None, data)

        group = _parse_group(d.pop('group'))

        is_deleted = d.pop('isDeleted')

        name = d.pop('name')

        type_ = ProfileType(d.pop('type'))

        uuid = d.pop('uuid')

        profile_short_info_schema = cls(
            group=group,
            is_deleted=is_deleted,
            name=name,
            type_=type_,
            uuid=uuid,
        )

        profile_short_info_schema.additional_properties = d
        return profile_short_info_schema

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
