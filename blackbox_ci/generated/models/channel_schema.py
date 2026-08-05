from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='ChannelSchema')


@_attrs_define
class ChannelSchema:
    """
    Attributes:
        http_verb (str):
        parameter_name (str):
        type_ (None | str):
    """

    http_verb: str
    parameter_name: str
    type_: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        http_verb = self.http_verb

        parameter_name = self.parameter_name

        type_: None | str
        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'httpVerb': http_verb,
                'parameterName': parameter_name,
                'type': type_,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        http_verb = d.pop('httpVerb')

        parameter_name = d.pop('parameterName')

        def _parse_type_(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        type_ = _parse_type_(d.pop('type'))

        channel_schema = cls(
            http_verb=http_verb,
            parameter_name=parameter_name,
            type_=type_,
        )

        channel_schema.additional_properties = d
        return channel_schema

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
