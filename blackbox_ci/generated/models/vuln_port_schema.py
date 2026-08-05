from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

from ..models.severity import Severity

T = TypeVar('T', bound='VulnPortSchema')


@_attrs_define
class VulnPortSchema:
    """
    Attributes:
        description (str):
        ip (str):
        port (int):
        severity (Severity):
    """

    description: str
    ip: str
    port: int
    severity: Severity
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        description = self.description

        ip = self.ip

        port = self.port

        severity = self.severity.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'description': description,
                'ip': ip,
                'port': port,
                'severity': severity,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        description = d.pop('description')

        ip = d.pop('ip')

        port = d.pop('port')

        severity = Severity(d.pop('severity'))

        vuln_port_schema = cls(
            description=description,
            ip=ip,
            port=port,
            severity=severity,
        )

        vuln_port_schema.additional_properties = d
        return vuln_port_schema

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
