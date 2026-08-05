from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..models.profile_type import ProfileType

if TYPE_CHECKING:
    from ..models.group_short_info_schema import GroupShortInfoSchema
    from ..models.profile_params_schema import ProfileParamsSchema


T = TypeVar('T', bound='ProfileFullInfoSchema')


@_attrs_define
class ProfileFullInfoSchema:
    """
    Attributes:
        group (GroupShortInfoSchema):
        is_deleted (bool):
        name (str):
        params (ProfileParamsSchema):
        type_ (ProfileType):
        uuid (UUID):
    """

    group: GroupShortInfoSchema
    is_deleted: bool
    name: str
    params: ProfileParamsSchema
    type_: ProfileType
    uuid: UUID
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group = self.group.to_dict()

        is_deleted = self.is_deleted

        name = self.name

        params = self.params.to_dict()

        type_ = self.type_.value

        uuid = str(self.uuid)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'group': group,
                'isDeleted': is_deleted,
                'name': name,
                'params': params,
                'type': type_,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_short_info_schema import GroupShortInfoSchema
        from ..models.profile_params_schema import ProfileParamsSchema

        d = dict(src_dict)
        group = GroupShortInfoSchema.from_dict(d.pop('group'))

        is_deleted = d.pop('isDeleted')

        name = d.pop('name')

        params = ProfileParamsSchema.from_dict(d.pop('params'))

        type_ = ProfileType(d.pop('type'))

        uuid = UUID(d.pop('uuid'))

        profile_full_info_schema = cls(
            group=group,
            is_deleted=is_deleted,
            name=name,
            params=params,
            type_=type_,
            uuid=uuid,
        )

        profile_full_info_schema.additional_properties = d
        return profile_full_info_schema

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
