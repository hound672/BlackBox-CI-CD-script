from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.api_key_place import ApiKeyPlace
from ..types import UNSET, Unset

T = TypeVar('T', bound='APIKeySchema')


@_attrs_define
class APIKeySchema:
    """
    Attributes:
        name (str):
        place (ApiKeyPlace):
        success_url (str):
        value (str):
        success_string (None | str | Unset):
    """

    name: str
    place: ApiKeyPlace
    success_url: str
    value: str
    success_string: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        place = self.place.value

        success_url = self.success_url

        value = self.value

        success_string: None | str | Unset
        if isinstance(self.success_string, Unset):
            success_string = UNSET
        else:
            success_string = self.success_string

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'name': name,
                'place': place,
                'successUrl': success_url,
                'value': value,
            }
        )
        if success_string is not UNSET:
            field_dict['successString'] = success_string

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop('name')

        place = ApiKeyPlace(d.pop('place'))

        success_url = d.pop('successUrl')

        value = d.pop('value')

        def _parse_success_string(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        success_string = _parse_success_string(d.pop('successString', UNSET))

        api_key_schema = cls(
            name=name,
            place=place,
            success_url=success_url,
            value=value,
            success_string=success_string,
        )

        api_key_schema.additional_properties = d
        return api_key_schema

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
