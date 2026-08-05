from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='HTTPBasicSchema')


@_attrs_define
class HTTPBasicSchema:
    """
    Attributes:
        password (str):
        username (str):
        test_string (None | str | Unset):
    """

    password: str
    username: str
    test_string: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        password = self.password

        username = self.username

        test_string: None | str | Unset
        if isinstance(self.test_string, Unset):
            test_string = UNSET
        else:
            test_string = self.test_string

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'password': password,
                'username': username,
            }
        )
        if test_string is not UNSET:
            field_dict['testString'] = test_string

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        password = d.pop('password')

        username = d.pop('username')

        def _parse_test_string(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        test_string = _parse_test_string(d.pop('testString', UNSET))

        http_basic_schema = cls(
            password=password,
            username=username,
            test_string=test_string,
        )

        http_basic_schema.additional_properties = d
        return http_basic_schema

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
