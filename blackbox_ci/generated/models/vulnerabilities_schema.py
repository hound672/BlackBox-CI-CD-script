from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vulnerability_stat_schema import VulnerabilityStatSchema


T = TypeVar('T', bound='VulnerabilitiesSchema')


@_attrs_define
class VulnerabilitiesSchema:
    """
    Attributes:
        high (VulnerabilityStatSchema):
        info (VulnerabilityStatSchema):
        low (VulnerabilityStatSchema):
        medium (VulnerabilityStatSchema):
    """

    high: VulnerabilityStatSchema
    info: VulnerabilityStatSchema
    low: VulnerabilityStatSchema
    medium: VulnerabilityStatSchema
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        high = self.high.to_dict()

        info = self.info.to_dict()

        low = self.low.to_dict()

        medium = self.medium.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'high': high,
                'info': info,
                'low': low,
                'medium': medium,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vulnerability_stat_schema import VulnerabilityStatSchema

        d = dict(src_dict)
        high = VulnerabilityStatSchema.from_dict(d.pop('high'))

        info = VulnerabilityStatSchema.from_dict(d.pop('info'))

        low = VulnerabilityStatSchema.from_dict(d.pop('low'))

        medium = VulnerabilityStatSchema.from_dict(d.pop('medium'))

        vulnerabilities_schema = cls(
            high=high,
            info=info,
            low=low,
            medium=medium,
        )

        vulnerabilities_schema.additional_properties = d
        return vulnerabilities_schema

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
