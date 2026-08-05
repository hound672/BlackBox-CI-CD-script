from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.profile_params_schema import ProfileParamsSchema


T = TypeVar('T', bound='ProfileCreateSchema')


@_attrs_define
class ProfileCreateSchema:
    """
    Attributes:
        base_profile_uuid (UUID):
        group_uuid (UUID):
        name (str):
        params (ProfileParamsSchema):
    """

    base_profile_uuid: UUID
    group_uuid: UUID
    name: str
    params: ProfileParamsSchema
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base_profile_uuid = str(self.base_profile_uuid)

        group_uuid = str(self.group_uuid)

        name = self.name

        params = self.params.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'baseProfileUUID': base_profile_uuid,
                'groupUUID': group_uuid,
                'name': name,
                'params': params,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.profile_params_schema import ProfileParamsSchema

        d = dict(src_dict)
        base_profile_uuid = UUID(d.pop('baseProfileUUID'))

        group_uuid = UUID(d.pop('groupUUID'))

        name = d.pop('name')

        params = ProfileParamsSchema.from_dict(d.pop('params'))

        profile_create_schema = cls(
            base_profile_uuid=base_profile_uuid,
            group_uuid=group_uuid,
            name=name,
            params=params,
        )

        profile_create_schema.additional_properties = d
        return profile_create_schema

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
