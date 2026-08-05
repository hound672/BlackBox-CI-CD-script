from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

from ..models.auth_data_status import AuthDataStatus
from ..models.scan_status import ScanStatus

if TYPE_CHECKING:
    from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
    from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
    from ..models.profile_short_info_schema import ProfileShortInfoSchema
    from ..models.vuln_perimeter_info_schema import VulnPerimeterInfoSchema
    from ..models.vulnerabilities_schema import VulnerabilitiesSchema


T = TypeVar('T', bound='ScanQueueProfilesSchema')


@_attrs_define
class ScanQueueProfilesSchema:
    """
    Attributes:
        api_profile (APIProfileShortInfoSchema | None):
        auth_status (AuthDataStatus):
        authentication (AuthSettingsInfoSchema | None):
        created_at (datetime.datetime):
        duration (float):
        error_reason (None | str):
        finished_at (datetime.datetime | None):
        kb_version (None | str):
        perimeter_scan (VulnPerimeterInfoSchema):
        profile (ProfileShortInfoSchema):
        progress (int):
        queue_position (int | None):
        score (float | None):
        started_at (datetime.datetime | None):
        status (ScanStatus):
        uuid (str):
        vuln_stats (VulnerabilitiesSchema):
    """

    api_profile: APIProfileShortInfoSchema | None
    auth_status: AuthDataStatus
    authentication: AuthSettingsInfoSchema | None
    created_at: datetime.datetime
    duration: float
    error_reason: None | str
    finished_at: datetime.datetime | None
    kb_version: None | str
    perimeter_scan: VulnPerimeterInfoSchema
    profile: ProfileShortInfoSchema
    progress: int
    queue_position: int | None
    score: float | None
    started_at: datetime.datetime | None
    status: ScanStatus
    uuid: str
    vuln_stats: VulnerabilitiesSchema
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
        from ..models.auth_settings_info_schema import AuthSettingsInfoSchema

        api_profile: dict[str, Any] | None
        if isinstance(self.api_profile, APIProfileShortInfoSchema):
            api_profile = self.api_profile.to_dict()
        else:
            api_profile = self.api_profile

        auth_status = self.auth_status.value

        authentication: dict[str, Any] | None
        if isinstance(self.authentication, AuthSettingsInfoSchema):
            authentication = self.authentication.to_dict()
        else:
            authentication = self.authentication

        created_at = self.created_at.isoformat()

        duration = self.duration

        error_reason: None | str
        error_reason = self.error_reason

        finished_at: None | str
        if isinstance(self.finished_at, datetime.datetime):
            finished_at = self.finished_at.isoformat()
        else:
            finished_at = self.finished_at

        kb_version: None | str
        kb_version = self.kb_version

        perimeter_scan = self.perimeter_scan.to_dict()

        profile = self.profile.to_dict()

        progress = self.progress

        queue_position: int | None
        queue_position = self.queue_position

        score: float | None
        score = self.score

        started_at: None | str
        if isinstance(self.started_at, datetime.datetime):
            started_at = self.started_at.isoformat()
        else:
            started_at = self.started_at

        status = self.status.value

        uuid = self.uuid

        vuln_stats = self.vuln_stats.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'apiProfile': api_profile,
                'authStatus': auth_status,
                'authentication': authentication,
                'createdAt': created_at,
                'duration': duration,
                'errorReason': error_reason,
                'finishedAt': finished_at,
                'kbVersion': kb_version,
                'perimeterScan': perimeter_scan,
                'profile': profile,
                'progress': progress,
                'queuePosition': queue_position,
                'score': score,
                'startedAt': started_at,
                'status': status,
                'uuid': uuid,
                'vulnStats': vuln_stats,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
        from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
        from ..models.profile_short_info_schema import ProfileShortInfoSchema
        from ..models.vuln_perimeter_info_schema import VulnPerimeterInfoSchema
        from ..models.vulnerabilities_schema import VulnerabilitiesSchema

        d = dict(src_dict)

        def _parse_api_profile(data: object) -> APIProfileShortInfoSchema | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                api_profile_type_0 = APIProfileShortInfoSchema.from_dict(data)

                return api_profile_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(APIProfileShortInfoSchema | None, data)

        api_profile = _parse_api_profile(d.pop('apiProfile'))

        auth_status = AuthDataStatus(d.pop('authStatus'))

        def _parse_authentication(data: object) -> AuthSettingsInfoSchema | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                authentication_type_0 = AuthSettingsInfoSchema.from_dict(data)

                return authentication_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AuthSettingsInfoSchema | None, data)

        authentication = _parse_authentication(d.pop('authentication'))

        created_at = isoparse(d.pop('createdAt'))

        duration = d.pop('duration')

        def _parse_error_reason(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        error_reason = _parse_error_reason(d.pop('errorReason'))

        def _parse_finished_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                finished_at_type_0 = isoparse(data)

                return finished_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        finished_at = _parse_finished_at(d.pop('finishedAt'))

        def _parse_kb_version(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        kb_version = _parse_kb_version(d.pop('kbVersion'))

        perimeter_scan = VulnPerimeterInfoSchema.from_dict(d.pop('perimeterScan'))

        profile = ProfileShortInfoSchema.from_dict(d.pop('profile'))

        progress = d.pop('progress')

        def _parse_queue_position(data: object) -> int | None:
            if data is None:
                return data
            return cast(int | None, data)

        queue_position = _parse_queue_position(d.pop('queuePosition'))

        def _parse_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        score = _parse_score(d.pop('score'))

        def _parse_started_at(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                started_at_type_0 = isoparse(data)

                return started_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        started_at = _parse_started_at(d.pop('startedAt'))

        status = ScanStatus(d.pop('status'))

        uuid = d.pop('uuid')

        vuln_stats = VulnerabilitiesSchema.from_dict(d.pop('vulnStats'))

        scan_queue_profiles_schema = cls(
            api_profile=api_profile,
            auth_status=auth_status,
            authentication=authentication,
            created_at=created_at,
            duration=duration,
            error_reason=error_reason,
            finished_at=finished_at,
            kb_version=kb_version,
            perimeter_scan=perimeter_scan,
            profile=profile,
            progress=progress,
            queue_position=queue_position,
            score=score,
            started_at=started_at,
            status=status,
            uuid=uuid,
            vuln_stats=vuln_stats,
        )

        scan_queue_profiles_schema.additional_properties = d
        return scan_queue_profiles_schema

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
