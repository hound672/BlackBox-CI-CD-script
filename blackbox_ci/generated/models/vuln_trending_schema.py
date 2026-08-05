from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

from ..models.severity import Severity

if TYPE_CHECKING:
    from ..models.vuln_template_info_schema import VulnTemplateInfoSchema


T = TypeVar('T', bound='VulnTrendingSchema')


@_attrs_define
class VulnTrendingSchema:
    """
    Attributes:
        created_at (datetime.datetime):
        request_raw (str):
        response_raw (str):
        severity (Severity):
        template_id (str):
        template_info (VulnTemplateInfoSchema):
        type_ (Literal['trending']):
        url_full (str):
        uuid (str):
    """

    created_at: datetime.datetime
    request_raw: str
    response_raw: str
    severity: Severity
    template_id: str
    template_info: VulnTemplateInfoSchema
    type_: Literal['trending']
    url_full: str
    uuid: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        created_at = self.created_at.isoformat()

        request_raw = self.request_raw

        response_raw = self.response_raw

        severity = self.severity.value

        template_id = self.template_id

        template_info = self.template_info.to_dict()

        type_ = self.type_

        url_full = self.url_full

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'createdAt': created_at,
                'requestRaw': request_raw,
                'responseRaw': response_raw,
                'severity': severity,
                'templateId': template_id,
                'templateInfo': template_info,
                'type': type_,
                'urlFull': url_full,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_template_info_schema import VulnTemplateInfoSchema

        d = dict(src_dict)
        created_at = isoparse(d.pop('createdAt'))

        request_raw = d.pop('requestRaw')

        response_raw = d.pop('responseRaw')

        severity = Severity(d.pop('severity'))

        template_id = d.pop('templateId')

        template_info = VulnTemplateInfoSchema.from_dict(d.pop('templateInfo'))

        type_ = cast(Literal['trending'], d.pop('type'))
        if type_ != 'trending':
            raise ValueError(f"type must match const 'trending', got '{type_}'")

        url_full = d.pop('urlFull')

        uuid = d.pop('uuid')

        vuln_trending_schema = cls(
            created_at=created_at,
            request_raw=request_raw,
            response_raw=response_raw,
            severity=severity,
            template_id=template_id,
            template_info=template_info,
            type_=type_,
            url_full=url_full,
            uuid=uuid,
        )

        vuln_trending_schema.additional_properties = d
        return vuln_trending_schema

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
