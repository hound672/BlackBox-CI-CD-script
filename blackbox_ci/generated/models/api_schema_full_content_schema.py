from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

from ..models.api_schema_content_types import APISchemaContentTypes

T = TypeVar('T', bound='APISchemaFullContentSchema')


@_attrs_define
class APISchemaFullContentSchema:
    """
    Attributes:
        data (str): link for type `link`, presigned url for others
        type_ (APISchemaContentTypes):
    """

    data: str
    type_: APISchemaContentTypes
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = self.data

        type_ = self.type_.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'data': data,
                'type': type_,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        data = d.pop('data')

        type_ = APISchemaContentTypes(d.pop('type'))

        api_schema_full_content_schema = cls(
            data=data,
            type_=type_,
        )

        api_schema_full_content_schema.additional_properties = d
        return api_schema_full_content_schema

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
