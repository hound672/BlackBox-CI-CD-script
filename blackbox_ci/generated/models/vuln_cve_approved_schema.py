from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='VulnCVEApprovedSchema')


@_attrs_define
class VulnCVEApprovedSchema:
    """
    Attributes:
        cve_id (str):
        cvss (float):
        cvss_vector (str):
        matches (list[str] | None):
        request_raw (None | str):
        response_raw (None | str):
        title (str):
        type_ (Literal['cve_approved']):
    """

    cve_id: str
    cvss: float
    cvss_vector: str
    matches: list[str] | None
    request_raw: None | str
    response_raw: None | str
    title: str
    type_: Literal['cve_approved']
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        cvss = self.cvss

        cvss_vector = self.cvss_vector

        matches: list[str] | None
        if isinstance(self.matches, list):
            matches = self.matches

        else:
            matches = self.matches

        request_raw: None | str
        request_raw = self.request_raw

        response_raw: None | str
        response_raw = self.response_raw

        title = self.title

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'cveId': cve_id,
                'cvss': cvss,
                'cvssVector': cvss_vector,
                'matches': matches,
                'requestRaw': request_raw,
                'responseRaw': response_raw,
                'title': title,
                'type': type_,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop('cveId')

        cvss = d.pop('cvss')

        cvss_vector = d.pop('cvssVector')

        def _parse_matches(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                matches_type_0 = cast(list[str], data)

                return matches_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        matches = _parse_matches(d.pop('matches'))

        def _parse_request_raw(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        request_raw = _parse_request_raw(d.pop('requestRaw'))

        def _parse_response_raw(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        response_raw = _parse_response_raw(d.pop('responseRaw'))

        title = d.pop('title')

        type_ = cast(Literal['cve_approved'], d.pop('type'))
        if type_ != 'cve_approved':
            raise ValueError(f"type must match const 'cve_approved', got '{type_}'")

        vuln_cve_approved_schema = cls(
            cve_id=cve_id,
            cvss=cvss,
            cvss_vector=cvss_vector,
            matches=matches,
            request_raw=request_raw,
            response_raw=response_raw,
            title=title,
            type_=type_,
        )

        vuln_cve_approved_schema.additional_properties = d
        return vuln_cve_approved_schema

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
