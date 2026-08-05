from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vuln_template_classification_schema import VulnTemplateClassificationSchema


T = TypeVar('T', bound='VulnTemplateInfoSchema')


@_attrs_define
class VulnTemplateInfoSchema:
    """
    Attributes:
        classification (None | VulnTemplateClassificationSchema):
        description (None | str):
        impact (None | str):
        name (str):
        reference (list[str] | None):
        remediation (None | str):
    """

    classification: None | VulnTemplateClassificationSchema
    description: None | str
    impact: None | str
    name: str
    reference: list[str] | None
    remediation: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.vuln_template_classification_schema import VulnTemplateClassificationSchema

        classification: dict[str, Any] | None
        if isinstance(self.classification, VulnTemplateClassificationSchema):
            classification = self.classification.to_dict()
        else:
            classification = self.classification

        description: None | str
        description = self.description

        impact: None | str
        impact = self.impact

        name = self.name

        reference: list[str] | None
        if isinstance(self.reference, list):
            reference = self.reference

        else:
            reference = self.reference

        remediation: None | str
        remediation = self.remediation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'classification': classification,
                'description': description,
                'impact': impact,
                'name': name,
                'reference': reference,
                'remediation': remediation,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_template_classification_schema import VulnTemplateClassificationSchema

        d = dict(src_dict)

        def _parse_classification(data: object) -> None | VulnTemplateClassificationSchema:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                classification_type_0 = VulnTemplateClassificationSchema.from_dict(data)

                return classification_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | VulnTemplateClassificationSchema, data)

        classification = _parse_classification(d.pop('classification'))

        def _parse_description(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        description = _parse_description(d.pop('description'))

        def _parse_impact(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        impact = _parse_impact(d.pop('impact'))

        name = d.pop('name')

        def _parse_reference(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                reference_type_0 = cast(list[str], data)

                return reference_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        reference = _parse_reference(d.pop('reference'))

        def _parse_remediation(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        remediation = _parse_remediation(d.pop('remediation'))

        vuln_template_info_schema = cls(
            classification=classification,
            description=description,
            impact=impact,
            name=name,
            reference=reference,
            remediation=remediation,
        )

        vuln_template_info_schema.additional_properties = d
        return vuln_template_info_schema

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
