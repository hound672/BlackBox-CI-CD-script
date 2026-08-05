from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='SiteCreateSchema')


@_attrs_define
class SiteCreateSchema:
    """
    Attributes:
        group_uuid (UUID):
        url (str):
        api_profile_uuid (None | Unset | UUID):
        authentication_uuid (None | Unset | UUID):
        name (None | str | Unset):
        profile_uuid (None | Unset | UUID):
    """

    group_uuid: UUID
    url: str
    api_profile_uuid: None | Unset | UUID = UNSET
    authentication_uuid: None | Unset | UUID = UNSET
    name: None | str | Unset = UNSET
    profile_uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group_uuid = str(self.group_uuid)

        url = self.url

        api_profile_uuid: None | str | Unset
        if isinstance(self.api_profile_uuid, Unset):
            api_profile_uuid = UNSET
        elif isinstance(self.api_profile_uuid, UUID):
            api_profile_uuid = str(self.api_profile_uuid)
        else:
            api_profile_uuid = self.api_profile_uuid

        authentication_uuid: None | str | Unset
        if isinstance(self.authentication_uuid, Unset):
            authentication_uuid = UNSET
        elif isinstance(self.authentication_uuid, UUID):
            authentication_uuid = str(self.authentication_uuid)
        else:
            authentication_uuid = self.authentication_uuid

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        profile_uuid: None | str | Unset
        if isinstance(self.profile_uuid, Unset):
            profile_uuid = UNSET
        elif isinstance(self.profile_uuid, UUID):
            profile_uuid = str(self.profile_uuid)
        else:
            profile_uuid = self.profile_uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'groupUUID': group_uuid,
                'url': url,
            }
        )
        if api_profile_uuid is not UNSET:
            field_dict['apiProfileUUID'] = api_profile_uuid
        if authentication_uuid is not UNSET:
            field_dict['authenticationUUID'] = authentication_uuid
        if name is not UNSET:
            field_dict['name'] = name
        if profile_uuid is not UNSET:
            field_dict['profileUUID'] = profile_uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        group_uuid = UUID(d.pop('groupUUID'))

        url = d.pop('url')

        def _parse_api_profile_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                api_profile_uuid_type_0 = UUID(data)

                return api_profile_uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        api_profile_uuid = _parse_api_profile_uuid(d.pop('apiProfileUUID', UNSET))

        def _parse_authentication_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                authentication_uuid_type_0 = UUID(data)

                return authentication_uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        authentication_uuid = _parse_authentication_uuid(d.pop('authenticationUUID', UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop('name', UNSET))

        def _parse_profile_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                profile_uuid_type_0 = UUID(data)

                return profile_uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        profile_uuid = _parse_profile_uuid(d.pop('profileUUID', UNSET))

        site_create_schema = cls(
            group_uuid=group_uuid,
            url=url,
            api_profile_uuid=api_profile_uuid,
            authentication_uuid=authentication_uuid,
            name=name,
            profile_uuid=profile_uuid,
        )

        site_create_schema.additional_properties = d
        return site_create_schema

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
