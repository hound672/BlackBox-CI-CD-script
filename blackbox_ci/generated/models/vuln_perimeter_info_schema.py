from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='VulnPerimeterInfoSchema')


@_attrs_define
class VulnPerimeterInfoSchema:
    """
    Attributes:
        enabled (bool):
        ports_count (int):
    """

    enabled: bool
    ports_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        enabled = self.enabled

        ports_count = self.ports_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'enabled': enabled,
                'portsCount': ports_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        enabled = d.pop('enabled')

        ports_count = d.pop('portsCount')

        vuln_perimeter_info_schema = cls(
            enabled=enabled,
            ports_count=ports_count,
        )

        vuln_perimeter_info_schema.additional_properties = d
        return vuln_perimeter_info_schema

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
