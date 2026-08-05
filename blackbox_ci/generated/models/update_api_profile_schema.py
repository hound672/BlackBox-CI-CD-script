from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='UpdateAPIProfileSchema')


@_attrs_define
class UpdateAPIProfileSchema:
    """
    Attributes:
        api_schemas (list[UUID] | None | Unset):
        name (None | str | Unset):
    """

    api_schemas: list[UUID] | None | Unset = UNSET
    name: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        api_schemas: list[str] | None | Unset
        if isinstance(self.api_schemas, Unset):
            api_schemas = UNSET
        elif isinstance(self.api_schemas, list):
            api_schemas = []
            for api_schemas_type_0_item_data in self.api_schemas:
                api_schemas_type_0_item = str(api_schemas_type_0_item_data)
                api_schemas.append(api_schemas_type_0_item)

        else:
            api_schemas = self.api_schemas

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if api_schemas is not UNSET:
            field_dict['apiSchemas'] = api_schemas
        if name is not UNSET:
            field_dict['name'] = name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_api_schemas(data: object) -> list[UUID] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                api_schemas_type_0 = []
                _api_schemas_type_0 = data
                for api_schemas_type_0_item_data in _api_schemas_type_0:
                    api_schemas_type_0_item = UUID(api_schemas_type_0_item_data)

                    api_schemas_type_0.append(api_schemas_type_0_item)

                return api_schemas_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[UUID] | None | Unset, data)

        api_schemas = _parse_api_schemas(d.pop('apiSchemas', UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop('name', UNSET))

        update_api_profile_schema = cls(
            api_schemas=api_schemas,
            name=name,
        )

        update_api_profile_schema.additional_properties = d
        return update_api_profile_schema

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
