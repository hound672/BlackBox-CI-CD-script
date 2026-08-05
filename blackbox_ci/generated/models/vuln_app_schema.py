from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='VulnAppSchema')


@_attrs_define
class VulnAppSchema:
    """
    Attributes:
        name (str):
        software (None | str):
        type_ (None | str):
        url (str):
        vendor (None | str):
        version (None | str):
    """

    name: str
    software: None | str
    type_: None | str
    url: str
    vendor: None | str
    version: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        software: None | str
        software = self.software

        type_: None | str
        type_ = self.type_

        url = self.url

        vendor: None | str
        vendor = self.vendor

        version: None | str
        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'name': name,
                'software': software,
                'type': type_,
                'url': url,
                'vendor': vendor,
                'version': version,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop('name')

        def _parse_software(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        software = _parse_software(d.pop('software'))

        def _parse_type_(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        type_ = _parse_type_(d.pop('type'))

        url = d.pop('url')

        def _parse_vendor(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        vendor = _parse_vendor(d.pop('vendor'))

        def _parse_version(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        version = _parse_version(d.pop('version'))

        vuln_app_schema = cls(
            name=name,
            software=software,
            type_=type_,
            url=url,
            vendor=vendor,
            version=version,
        )

        vuln_app_schema.additional_properties = d
        return vuln_app_schema

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
