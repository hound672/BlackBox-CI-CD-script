from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.severity import Severity
from ..models.vuln_category_name import VulnCategoryName
from ..models.vulnerability_issue import VulnerabilityIssue
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.vuln_apps_schema import VulnAppsSchema
    from ..models.vuln_cve_approved_schema import VulnCVEApprovedSchema
    from ..models.vuln_cve_schema import VulnCVESchema
    from ..models.vuln_error_page_schema import VulnErrorPageSchema
    from ..models.vuln_trending_schema import VulnTrendingSchema
    from ..models.vuln_we_schema import VulnWESchema


T = TypeVar('T', bound='VulnGroupSchema')


@_attrs_define
class VulnGroupSchema:
    """
    Attributes:
        category_locale_key (VulnCategoryName):
        count (int):
        group_title (str):
        issue_type (VulnerabilityIssue):
        request_key (None | str):
        severity (Severity):
        vulnerability (VulnAppsSchema | VulnCVEApprovedSchema | VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema
            | VulnWESchema):
        suspicion_count (int | Unset):  Default: 0.
    """

    category_locale_key: VulnCategoryName
    count: int
    group_title: str
    issue_type: VulnerabilityIssue
    request_key: None | str
    severity: Severity
    vulnerability: (
        VulnAppsSchema | VulnCVEApprovedSchema | VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema | VulnWESchema
    )
    suspicion_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.vuln_apps_schema import VulnAppsSchema
        from ..models.vuln_cve_approved_schema import VulnCVEApprovedSchema
        from ..models.vuln_cve_schema import VulnCVESchema
        from ..models.vuln_error_page_schema import VulnErrorPageSchema
        from ..models.vuln_trending_schema import VulnTrendingSchema

        category_locale_key = self.category_locale_key.value

        count = self.count

        group_title = self.group_title

        issue_type = self.issue_type.value

        request_key: None | str
        request_key = self.request_key

        severity = self.severity.value

        vulnerability: dict[str, Any]
        if (
            isinstance(self.vulnerability, VulnAppsSchema)
            or isinstance(self.vulnerability, VulnCVESchema)
            or isinstance(self.vulnerability, VulnCVEApprovedSchema)
            or isinstance(self.vulnerability, VulnErrorPageSchema)
            or isinstance(self.vulnerability, VulnTrendingSchema)
        ):
            vulnerability = self.vulnerability.to_dict()
        else:
            vulnerability = self.vulnerability.to_dict()

        suspicion_count = self.suspicion_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'categoryLocaleKey': category_locale_key,
                'count': count,
                'groupTitle': group_title,
                'issueType': issue_type,
                'requestKey': request_key,
                'severity': severity,
                'vulnerability': vulnerability,
            }
        )
        if suspicion_count is not UNSET:
            field_dict['suspicionCount'] = suspicion_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_apps_schema import VulnAppsSchema
        from ..models.vuln_cve_approved_schema import VulnCVEApprovedSchema
        from ..models.vuln_cve_schema import VulnCVESchema
        from ..models.vuln_error_page_schema import VulnErrorPageSchema
        from ..models.vuln_trending_schema import VulnTrendingSchema
        from ..models.vuln_we_schema import VulnWESchema

        d = dict(src_dict)
        category_locale_key = VulnCategoryName(d.pop('categoryLocaleKey'))

        count = d.pop('count')

        group_title = d.pop('groupTitle')

        issue_type = VulnerabilityIssue(d.pop('issueType'))

        def _parse_request_key(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        request_key = _parse_request_key(d.pop('requestKey'))

        severity = Severity(d.pop('severity'))

        def _parse_vulnerability(
            data: object,
        ) -> (
            VulnAppsSchema
            | VulnCVEApprovedSchema
            | VulnCVESchema
            | VulnErrorPageSchema
            | VulnTrendingSchema
            | VulnWESchema
        ):
            try:
                if not isinstance(data, dict):
                    raise TypeError
                vulnerability_type_0 = VulnAppsSchema.from_dict(data)

                return vulnerability_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, dict):
                    raise TypeError
                vulnerability_type_1 = VulnCVESchema.from_dict(data)

                return vulnerability_type_1
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, dict):
                    raise TypeError
                vulnerability_type_2 = VulnCVEApprovedSchema.from_dict(data)

                return vulnerability_type_2
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, dict):
                    raise TypeError
                vulnerability_type_3 = VulnErrorPageSchema.from_dict(data)

                return vulnerability_type_3
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            try:
                if not isinstance(data, dict):
                    raise TypeError
                vulnerability_type_4 = VulnTrendingSchema.from_dict(data)

                return vulnerability_type_4
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            if not isinstance(data, dict):
                raise TypeError
            vulnerability_type_5 = VulnWESchema.from_dict(data)

            return vulnerability_type_5

        vulnerability = _parse_vulnerability(d.pop('vulnerability'))

        suspicion_count = d.pop('suspicionCount', UNSET)

        vuln_group_schema = cls(
            category_locale_key=category_locale_key,
            count=count,
            group_title=group_title,
            issue_type=issue_type,
            request_key=request_key,
            severity=severity,
            vulnerability=vulnerability,
            suspicion_count=suspicion_count,
        )

        vuln_group_schema.additional_properties = d
        return vuln_group_schema

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
