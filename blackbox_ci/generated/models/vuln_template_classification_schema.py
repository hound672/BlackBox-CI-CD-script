from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

T = TypeVar('T', bound='VulnTemplateClassificationSchema')


@_attrs_define
class VulnTemplateClassificationSchema:
    """
    Attributes:
        cve_id (list[str] | None):
        cvss_metrics (None | str):
        cvss_score (float | None):
        cwe_id (list[str] | None):
        epss_percentile (float | None):
        epss_score (float | None):
    """

    cve_id: list[str] | None
    cvss_metrics: None | str
    cvss_score: float | None
    cwe_id: list[str] | None
    epss_percentile: float | None
    epss_score: float | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id: list[str] | None
        if isinstance(self.cve_id, list):
            cve_id = self.cve_id

        else:
            cve_id = self.cve_id

        cvss_metrics: None | str
        cvss_metrics = self.cvss_metrics

        cvss_score: float | None
        cvss_score = self.cvss_score

        cwe_id: list[str] | None
        if isinstance(self.cwe_id, list):
            cwe_id = self.cwe_id

        else:
            cwe_id = self.cwe_id

        epss_percentile: float | None
        epss_percentile = self.epss_percentile

        epss_score: float | None
        epss_score = self.epss_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'cveId': cve_id,
                'cvssMetrics': cvss_metrics,
                'cvssScore': cvss_score,
                'cweId': cwe_id,
                'epssPercentile': epss_percentile,
                'epssScore': epss_score,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cve_id(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                cve_id_type_0 = cast(list[str], data)

                return cve_id_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        cve_id = _parse_cve_id(d.pop('cveId'))

        def _parse_cvss_metrics(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cvss_metrics = _parse_cvss_metrics(d.pop('cvssMetrics'))

        def _parse_cvss_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        cvss_score = _parse_cvss_score(d.pop('cvssScore'))

        def _parse_cwe_id(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                cwe_id_type_0 = cast(list[str], data)

                return cwe_id_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        cwe_id = _parse_cwe_id(d.pop('cweId'))

        def _parse_epss_percentile(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        epss_percentile = _parse_epss_percentile(d.pop('epssPercentile'))

        def _parse_epss_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        epss_score = _parse_epss_score(d.pop('epssScore'))

        vuln_template_classification_schema = cls(
            cve_id=cve_id,
            cvss_metrics=cvss_metrics,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            epss_percentile=epss_percentile,
            epss_score=epss_score,
        )

        vuln_template_classification_schema.additional_properties = d
        return vuln_template_classification_schema

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
