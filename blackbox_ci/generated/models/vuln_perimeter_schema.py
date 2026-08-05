from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vuln_port_schema import VulnPortSchema


T = TypeVar('T', bound='VulnPerimeterSchema')


@_attrs_define
class VulnPerimeterSchema:
    """
    Attributes:
        ports (list[VulnPortSchema]):
        subdomain (str):
    """

    ports: list[VulnPortSchema]
    subdomain: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ports = []
        for ports_item_data in self.ports:
            ports_item = ports_item_data.to_dict()
            ports.append(ports_item)

        subdomain = self.subdomain

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'ports': ports,
                'subdomain': subdomain,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_port_schema import VulnPortSchema

        d = dict(src_dict)
        ports = []
        _ports = d.pop('ports')
        for ports_item_data in _ports:
            ports_item = VulnPortSchema.from_dict(ports_item_data)

            ports.append(ports_item)

        subdomain = d.pop('subdomain')

        vuln_perimeter_schema = cls(
            ports=ports,
            subdomain=subdomain,
        )

        vuln_perimeter_schema.additional_properties = d
        return vuln_perimeter_schema

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
