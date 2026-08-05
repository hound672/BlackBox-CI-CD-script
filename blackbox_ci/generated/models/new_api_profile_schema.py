from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='NewAPIProfileSchema')


@_attrs_define
class NewAPIProfileSchema:
    """
    Attributes:
        api_schemas (list[UUID]):
        group_uuid (UUID):
        name (str):
    """

    api_schemas: list[UUID]
    group_uuid: UUID
    name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        api_schemas = []
        for api_schemas_item_data in self.api_schemas:
            api_schemas_item = str(api_schemas_item_data)
            api_schemas.append(api_schemas_item)

        group_uuid = str(self.group_uuid)

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'apiSchemas': api_schemas,
                'groupUUID': group_uuid,
                'name': name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        api_schemas = []
        _api_schemas = d.pop('apiSchemas')
        for api_schemas_item_data in _api_schemas:
            api_schemas_item = UUID(api_schemas_item_data)

            api_schemas.append(api_schemas_item)

        group_uuid = UUID(d.pop('groupUUID'))

        name = d.pop('name')

        new_api_profile_schema = cls(
            api_schemas=api_schemas,
            group_uuid=group_uuid,
            name=name,
        )

        new_api_profile_schema.additional_properties = d
        return new_api_profile_schema

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
