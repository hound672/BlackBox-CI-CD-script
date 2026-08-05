from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..models.authentication_type import AuthenticationType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.api_key_schema import APIKeySchema
    from ..models.bearer_schema import BearerSchema
    from ..models.html_auto_form_schema import HTMLAutoFormSchema
    from ..models.html_form_based_schema import HTMLFormBasedSchema
    from ..models.http_basic_schema import HTTPBasicSchema
    from ..models.raw_cookie_schema import RawCookieSchema


T = TypeVar('T', bound='AuthProfileCreateSchema')


@_attrs_define
class AuthProfileCreateSchema:
    """
    Attributes:
        group_uuid (UUID):
        name (str):
        type_ (AuthenticationType):
        api_key (APIKeySchema | None | Unset):
        bearer (BearerSchema | None | Unset):
        html_auto_form (HTMLAutoFormSchema | None | Unset):
        html_form_based (HTMLFormBasedSchema | None | Unset):
        http_basic (HTTPBasicSchema | None | Unset):
        raw_cookie (None | RawCookieSchema | Unset):
    """

    group_uuid: UUID
    name: str
    type_: AuthenticationType
    api_key: APIKeySchema | None | Unset = UNSET
    bearer: BearerSchema | None | Unset = UNSET
    html_auto_form: HTMLAutoFormSchema | None | Unset = UNSET
    html_form_based: HTMLFormBasedSchema | None | Unset = UNSET
    http_basic: HTTPBasicSchema | None | Unset = UNSET
    raw_cookie: None | RawCookieSchema | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_key_schema import APIKeySchema
        from ..models.bearer_schema import BearerSchema
        from ..models.html_auto_form_schema import HTMLAutoFormSchema
        from ..models.html_form_based_schema import HTMLFormBasedSchema
        from ..models.http_basic_schema import HTTPBasicSchema
        from ..models.raw_cookie_schema import RawCookieSchema

        group_uuid = str(self.group_uuid)

        name = self.name

        type_ = self.type_.value

        api_key: dict[str, Any] | None | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        elif isinstance(self.api_key, APIKeySchema):
            api_key = self.api_key.to_dict()
        else:
            api_key = self.api_key

        bearer: dict[str, Any] | None | Unset
        if isinstance(self.bearer, Unset):
            bearer = UNSET
        elif isinstance(self.bearer, BearerSchema):
            bearer = self.bearer.to_dict()
        else:
            bearer = self.bearer

        html_auto_form: dict[str, Any] | None | Unset
        if isinstance(self.html_auto_form, Unset):
            html_auto_form = UNSET
        elif isinstance(self.html_auto_form, HTMLAutoFormSchema):
            html_auto_form = self.html_auto_form.to_dict()
        else:
            html_auto_form = self.html_auto_form

        html_form_based: dict[str, Any] | None | Unset
        if isinstance(self.html_form_based, Unset):
            html_form_based = UNSET
        elif isinstance(self.html_form_based, HTMLFormBasedSchema):
            html_form_based = self.html_form_based.to_dict()
        else:
            html_form_based = self.html_form_based

        http_basic: dict[str, Any] | None | Unset
        if isinstance(self.http_basic, Unset):
            http_basic = UNSET
        elif isinstance(self.http_basic, HTTPBasicSchema):
            http_basic = self.http_basic.to_dict()
        else:
            http_basic = self.http_basic

        raw_cookie: dict[str, Any] | None | Unset
        if isinstance(self.raw_cookie, Unset):
            raw_cookie = UNSET
        elif isinstance(self.raw_cookie, RawCookieSchema):
            raw_cookie = self.raw_cookie.to_dict()
        else:
            raw_cookie = self.raw_cookie

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'groupUUID': group_uuid,
                'name': name,
                'type': type_,
            }
        )
        if api_key is not UNSET:
            field_dict['apiKey'] = api_key
        if bearer is not UNSET:
            field_dict['bearer'] = bearer
        if html_auto_form is not UNSET:
            field_dict['htmlAutoForm'] = html_auto_form
        if html_form_based is not UNSET:
            field_dict['htmlFormBased'] = html_form_based
        if http_basic is not UNSET:
            field_dict['httpBasic'] = http_basic
        if raw_cookie is not UNSET:
            field_dict['rawCookie'] = raw_cookie

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_key_schema import APIKeySchema
        from ..models.bearer_schema import BearerSchema
        from ..models.html_auto_form_schema import HTMLAutoFormSchema
        from ..models.html_form_based_schema import HTMLFormBasedSchema
        from ..models.http_basic_schema import HTTPBasicSchema
        from ..models.raw_cookie_schema import RawCookieSchema

        d = dict(src_dict)
        group_uuid = UUID(d.pop('groupUUID'))

        name = d.pop('name')

        type_ = AuthenticationType(d.pop('type'))

        def _parse_api_key(data: object) -> APIKeySchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                api_key_type_0 = APIKeySchema.from_dict(data)

                return api_key_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(APIKeySchema | None | Unset, data)

        api_key = _parse_api_key(d.pop('apiKey', UNSET))

        def _parse_bearer(data: object) -> BearerSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                bearer_type_0 = BearerSchema.from_dict(data)

                return bearer_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BearerSchema | None | Unset, data)

        bearer = _parse_bearer(d.pop('bearer', UNSET))

        def _parse_html_auto_form(data: object) -> HTMLAutoFormSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                html_auto_form_type_0 = HTMLAutoFormSchema.from_dict(data)

                return html_auto_form_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HTMLAutoFormSchema | None | Unset, data)

        html_auto_form = _parse_html_auto_form(d.pop('htmlAutoForm', UNSET))

        def _parse_html_form_based(data: object) -> HTMLFormBasedSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                html_form_based_type_0 = HTMLFormBasedSchema.from_dict(data)

                return html_form_based_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HTMLFormBasedSchema | None | Unset, data)

        html_form_based = _parse_html_form_based(d.pop('htmlFormBased', UNSET))

        def _parse_http_basic(data: object) -> HTTPBasicSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                http_basic_type_0 = HTTPBasicSchema.from_dict(data)

                return http_basic_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HTTPBasicSchema | None | Unset, data)

        http_basic = _parse_http_basic(d.pop('httpBasic', UNSET))

        def _parse_raw_cookie(data: object) -> None | RawCookieSchema | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                raw_cookie_type_0 = RawCookieSchema.from_dict(data)

                return raw_cookie_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RawCookieSchema | Unset, data)

        raw_cookie = _parse_raw_cookie(d.pop('rawCookie', UNSET))

        auth_profile_create_schema = cls(
            group_uuid=group_uuid,
            name=name,
            type_=type_,
            api_key=api_key,
            bearer=bearer,
            html_auto_form=html_auto_form,
            html_form_based=html_form_based,
            http_basic=http_basic,
            raw_cookie=raw_cookie,
        )

        auth_profile_create_schema.additional_properties = d
        return auth_profile_create_schema

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
