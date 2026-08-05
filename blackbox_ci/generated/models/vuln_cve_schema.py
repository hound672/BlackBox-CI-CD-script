from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='VulnCVESchema')


@_attrs_define
class VulnCVESchema:
    """
    Attributes:
        cve_id (str):
        cvss (float):
        cvss_vector (str):
        title (str):
        type_ (Literal['cve']):
        uuid (str):
    """

    cve_id: str
    cvss: float
    cvss_vector: str
    title: str
    type_: Literal['cve']
    uuid: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        cvss = self.cvss

        cvss_vector = self.cvss_vector

        title = self.title

        type_ = self.type_

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'cveId': cve_id,
                'cvss': cvss,
                'cvssVector': cvss_vector,
                'title': title,
                'type': type_,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop('cveId')

        cvss = d.pop('cvss')

        cvss_vector = d.pop('cvssVector')

        title = d.pop('title')

        type_ = cast(Literal['cve'], d.pop('type'))
        if type_ != 'cve':
            raise ValueError(f"type must match const 'cve', got '{type_}'")

        uuid = d.pop('uuid')

        vuln_cve_schema = cls(
            cve_id=cve_id,
            cvss=cvss,
            cvss_vector=cvss_vector,
            title=title,
            type_=type_,
            uuid=uuid,
        )

        vuln_cve_schema.additional_properties = d
        return vuln_cve_schema

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
