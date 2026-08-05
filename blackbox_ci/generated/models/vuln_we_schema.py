from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

from ..models.severity import Severity
from ..models.vulnerability_confidence_levels import VulnerabilityConfidenceLevels

if TYPE_CHECKING:
    from ..models.channel_schema import ChannelSchema
    from ..models.vuln_matches_schema import VulnMatchesSchema


T = TypeVar('T', bound='VulnWESchema')


@_attrs_define
class VulnWESchema:
    """
    Attributes:
        channel (ChannelSchema | None):
        confidence (VulnerabilityConfidenceLevels):
        created_at (datetime.datetime):
        false_positive (bool):
        fixed (bool):
        matches (None | VulnMatchesSchema):
        request_raw (None | str):
        response_raw (None | str):
        response_time (float):
        severity (Severity):
        starred (bool):
        type_ (Literal['issue']):
        url_full (None | str):
        url_rel (str):
        uuid (str):
        vector (None | str):
    """

    channel: ChannelSchema | None
    confidence: VulnerabilityConfidenceLevels
    created_at: datetime.datetime
    false_positive: bool
    fixed: bool
    matches: None | VulnMatchesSchema
    request_raw: None | str
    response_raw: None | str
    response_time: float
    severity: Severity
    starred: bool
    type_: Literal['issue']
    url_full: None | str
    url_rel: str
    uuid: str
    vector: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.channel_schema import ChannelSchema
        from ..models.vuln_matches_schema import VulnMatchesSchema

        channel: dict[str, Any] | None
        if isinstance(self.channel, ChannelSchema):
            channel = self.channel.to_dict()
        else:
            channel = self.channel

        confidence = self.confidence.value

        created_at = self.created_at.isoformat()

        false_positive = self.false_positive

        fixed = self.fixed

        matches: dict[str, Any] | None
        if isinstance(self.matches, VulnMatchesSchema):
            matches = self.matches.to_dict()
        else:
            matches = self.matches

        request_raw: None | str
        request_raw = self.request_raw

        response_raw: None | str
        response_raw = self.response_raw

        response_time = self.response_time

        severity = self.severity.value

        starred = self.starred

        type_ = self.type_

        url_full: None | str
        url_full = self.url_full

        url_rel = self.url_rel

        uuid = self.uuid

        vector: None | str
        vector = self.vector

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'channel': channel,
                'confidence': confidence,
                'createdAt': created_at,
                'falsePositive': false_positive,
                'fixed': fixed,
                'matches': matches,
                'requestRaw': request_raw,
                'responseRaw': response_raw,
                'responseTime': response_time,
                'severity': severity,
                'starred': starred,
                'type': type_,
                'urlFull': url_full,
                'urlRel': url_rel,
                'uuid': uuid,
                'vector': vector,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.channel_schema import ChannelSchema
        from ..models.vuln_matches_schema import VulnMatchesSchema

        d = dict(src_dict)

        def _parse_channel(data: object) -> ChannelSchema | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                channel_type_0 = ChannelSchema.from_dict(data)

                return channel_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ChannelSchema | None, data)

        channel = _parse_channel(d.pop('channel'))

        confidence = VulnerabilityConfidenceLevels(d.pop('confidence'))

        created_at = isoparse(d.pop('createdAt'))

        false_positive = d.pop('falsePositive')

        fixed = d.pop('fixed')

        def _parse_matches(data: object) -> None | VulnMatchesSchema:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                matches_type_0 = VulnMatchesSchema.from_dict(data)

                return matches_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | VulnMatchesSchema, data)

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

        response_time = d.pop('responseTime')

        severity = Severity(d.pop('severity'))

        starred = d.pop('starred')

        type_ = cast(Literal['issue'], d.pop('type'))
        if type_ != 'issue':
            raise ValueError(f"type must match const 'issue', got '{type_}'")

        def _parse_url_full(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        url_full = _parse_url_full(d.pop('urlFull'))

        url_rel = d.pop('urlRel')

        uuid = d.pop('uuid')

        def _parse_vector(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        vector = _parse_vector(d.pop('vector'))

        vuln_we_schema = cls(
            channel=channel,
            confidence=confidence,
            created_at=created_at,
            false_positive=false_positive,
            fixed=fixed,
            matches=matches,
            request_raw=request_raw,
            response_raw=response_raw,
            response_time=response_time,
            severity=severity,
            starred=starred,
            type_=type_,
            url_full=url_full,
            url_rel=url_rel,
            uuid=uuid,
            vector=vector,
        )

        vuln_we_schema.additional_properties = d
        return vuln_we_schema

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
