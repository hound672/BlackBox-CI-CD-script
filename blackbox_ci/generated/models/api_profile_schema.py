from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.api_schema_short_schema import APISchemaShortSchema
    from ..models.group_short_info_schema import GroupShortInfoSchema


T = TypeVar('T', bound='APIProfileSchema')


@_attrs_define
class APIProfileSchema:
    """
    Attributes:
        api_schemas (list[APISchemaShortSchema]):
        created_at (datetime.datetime):
        group (GroupShortInfoSchema):
        name (str):
        uuid (str):
    """

    api_schemas: list[APISchemaShortSchema]
    created_at: datetime.datetime
    group: GroupShortInfoSchema
    name: str
    uuid: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        api_schemas = []
        for api_schemas_item_data in self.api_schemas:
            api_schemas_item = api_schemas_item_data.to_dict()
            api_schemas.append(api_schemas_item)

        created_at = self.created_at.isoformat()

        group = self.group.to_dict()

        name = self.name

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'apiSchemas': api_schemas,
                'createdAt': created_at,
                'group': group,
                'name': name,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_schema_short_schema import APISchemaShortSchema
        from ..models.group_short_info_schema import GroupShortInfoSchema

        d = dict(src_dict)
        api_schemas = []
        _api_schemas = d.pop('apiSchemas')
        for api_schemas_item_data in _api_schemas:
            api_schemas_item = APISchemaShortSchema.from_dict(api_schemas_item_data)

            api_schemas.append(api_schemas_item)

        created_at = isoparse(d.pop('createdAt'))

        group = GroupShortInfoSchema.from_dict(d.pop('group'))

        name = d.pop('name')

        uuid = d.pop('uuid')

        api_profile_schema = cls(
            api_schemas=api_schemas,
            created_at=created_at,
            group=group,
            name=name,
            uuid=uuid,
        )

        api_profile_schema.additional_properties = d
        return api_profile_schema

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
