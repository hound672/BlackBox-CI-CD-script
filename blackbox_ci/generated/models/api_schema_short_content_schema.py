from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.api_schema_content_types import APISchemaContentTypes
from ..types import UNSET, Unset

T = TypeVar('T', bound='APISchemaShortContentSchema')


@_attrs_define
class APISchemaShortContentSchema:
    """
    Attributes:
        type_ (APISchemaContentTypes):
        data (None | str | Unset): link for type `link`, null for others
    """

    type_: APISchemaContentTypes
    data: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        data: None | str | Unset
        if isinstance(self.data, Unset):
            data = UNSET
        else:
            data = self.data

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'type': type_,
            }
        )
        if data is not UNSET:
            field_dict['data'] = data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = APISchemaContentTypes(d.pop('type'))

        def _parse_data(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        data = _parse_data(d.pop('data', UNSET))

        api_schema_short_content_schema = cls(
            type_=type_,
            data=data,
        )

        api_schema_short_content_schema.additional_properties = d
        return api_schema_short_content_schema

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
