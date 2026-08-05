from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

from ..models.auth_data_status import AuthDataStatus
from ..models.request_full_scan_status import RequestFullScanStatus

if TYPE_CHECKING:
    from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
    from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
    from ..models.group_short_info_schema import GroupShortInfoSchema
    from ..models.profile_short_info_schema import ProfileShortInfoSchema
    from ..models.scan_queue_profiles_schema import ScanQueueProfilesSchema


T = TypeVar('T', bound='SiteSchema')


@_attrs_define
class SiteSchema:
    """
    Attributes:
        api_profile (APIProfileShortInfoSchema | None):
        auth_status (AuthDataStatus):
        authentication (AuthSettingsInfoSchema | None):
        created_at (datetime.datetime):
        group (GroupShortInfoSchema):
        last_scan (None | ScanQueueProfilesSchema):
        name (str):
        profile (ProfileShortInfoSchema):
        request_full_scan_status (None | RequestFullScanStatus):
        url (str):
        uuid (UUID):
        verified (bool):
    """

    api_profile: APIProfileShortInfoSchema | None
    auth_status: AuthDataStatus
    authentication: AuthSettingsInfoSchema | None
    created_at: datetime.datetime
    group: GroupShortInfoSchema
    last_scan: None | ScanQueueProfilesSchema
    name: str
    profile: ProfileShortInfoSchema
    request_full_scan_status: None | RequestFullScanStatus
    url: str
    uuid: UUID
    verified: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
        from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
        from ..models.scan_queue_profiles_schema import ScanQueueProfilesSchema

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

        group = self.group.to_dict()

        last_scan: dict[str, Any] | None
        if isinstance(self.last_scan, ScanQueueProfilesSchema):
            last_scan = self.last_scan.to_dict()
        else:
            last_scan = self.last_scan

        name = self.name

        profile = self.profile.to_dict()

        request_full_scan_status: None | str
        if isinstance(self.request_full_scan_status, RequestFullScanStatus):
            request_full_scan_status = self.request_full_scan_status.value
        else:
            request_full_scan_status = self.request_full_scan_status

        url = self.url

        uuid = str(self.uuid)

        verified = self.verified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'apiProfile': api_profile,
                'authStatus': auth_status,
                'authentication': authentication,
                'createdAt': created_at,
                'group': group,
                'lastScan': last_scan,
                'name': name,
                'profile': profile,
                'requestFullScanStatus': request_full_scan_status,
                'url': url,
                'uuid': uuid,
                'verified': verified,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
        from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
        from ..models.group_short_info_schema import GroupShortInfoSchema
        from ..models.profile_short_info_schema import ProfileShortInfoSchema
        from ..models.scan_queue_profiles_schema import ScanQueueProfilesSchema

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

        group = GroupShortInfoSchema.from_dict(d.pop('group'))

        def _parse_last_scan(data: object) -> None | ScanQueueProfilesSchema:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                last_scan_type_0 = ScanQueueProfilesSchema.from_dict(data)

                return last_scan_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ScanQueueProfilesSchema, data)

        last_scan = _parse_last_scan(d.pop('lastScan'))

        name = d.pop('name')

        profile = ProfileShortInfoSchema.from_dict(d.pop('profile'))

        def _parse_request_full_scan_status(data: object) -> None | RequestFullScanStatus:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                request_full_scan_status_type_0 = RequestFullScanStatus(data)

                return request_full_scan_status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RequestFullScanStatus, data)

        request_full_scan_status = _parse_request_full_scan_status(d.pop('requestFullScanStatus'))

        url = d.pop('url')

        uuid = UUID(d.pop('uuid'))

        verified = d.pop('verified')

        site_schema = cls(
            api_profile=api_profile,
            auth_status=auth_status,
            authentication=authentication,
            created_at=created_at,
            group=group,
            last_scan=last_scan,
            name=name,
            profile=profile,
            request_full_scan_status=request_full_scan_status,
            url=url,
            uuid=uuid,
            verified=verified,
        )

        site_schema.additional_properties = d
        return site_schema

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
