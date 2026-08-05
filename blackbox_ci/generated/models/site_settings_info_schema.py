from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
    from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
    from ..models.profile_short_info_schema import ProfileShortInfoSchema


T = TypeVar('T', bound='SiteSettingsInfoSchema')


@_attrs_define
class SiteSettingsInfoSchema:
    """
    Attributes:
        api_profile (APIProfileShortInfoSchema | None):
        authentication (AuthSettingsInfoSchema | None):
        name (str):
        profile (ProfileShortInfoSchema):
        url (str):
    """

    api_profile: APIProfileShortInfoSchema | None
    authentication: AuthSettingsInfoSchema | None
    name: str
    profile: ProfileShortInfoSchema
    url: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
        from ..models.auth_settings_info_schema import AuthSettingsInfoSchema

        api_profile: dict[str, Any] | None
        if isinstance(self.api_profile, APIProfileShortInfoSchema):
            api_profile = self.api_profile.to_dict()
        else:
            api_profile = self.api_profile

        authentication: dict[str, Any] | None
        if isinstance(self.authentication, AuthSettingsInfoSchema):
            authentication = self.authentication.to_dict()
        else:
            authentication = self.authentication

        name = self.name

        profile = self.profile.to_dict()

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'apiProfile': api_profile,
                'authentication': authentication,
                'name': name,
                'profile': profile,
                'url': url,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_profile_short_info_schema import APIProfileShortInfoSchema
        from ..models.auth_settings_info_schema import AuthSettingsInfoSchema
        from ..models.profile_short_info_schema import ProfileShortInfoSchema

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

        name = d.pop('name')

        profile = ProfileShortInfoSchema.from_dict(d.pop('profile'))

        url = d.pop('url')

        site_settings_info_schema = cls(
            api_profile=api_profile,
            authentication=authentication,
            name=name,
            profile=profile,
            url=url,
        )

        site_settings_info_schema.additional_properties = d
        return site_settings_info_schema

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
