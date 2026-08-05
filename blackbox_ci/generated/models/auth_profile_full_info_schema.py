from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.authentication_type import AuthenticationType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.api_key_info_schema import APIKeyInfoSchema
    from ..models.bearer_info_schema import BearerInfoSchema
    from ..models.group_short_info_schema import GroupShortInfoSchema
    from ..models.html_auto_form_info_schema import HTMLAutoFormInfoSchema
    from ..models.html_form_based_info_schema import HTMLFormBasedInfoSchema
    from ..models.http_basic_info_schema import HTTPBasicInfoSchema
    from ..models.raw_cookie_info_schema import RawCookieInfoSchema


T = TypeVar('T', bound='AuthProfileFullInfoSchema')


@_attrs_define
class AuthProfileFullInfoSchema:
    """
    Attributes:
        group (GroupShortInfoSchema):
        name (str):
        type_ (AuthenticationType):
        api_key (APIKeyInfoSchema | None | Unset):
        bearer (BearerInfoSchema | None | Unset):
        html_auto_form (HTMLAutoFormInfoSchema | None | Unset):
        html_form_based (HTMLFormBasedInfoSchema | None | Unset):
        http_basic (HTTPBasicInfoSchema | None | Unset):
        raw_cookie (None | RawCookieInfoSchema | Unset):
    """

    group: GroupShortInfoSchema
    name: str
    type_: AuthenticationType
    api_key: APIKeyInfoSchema | None | Unset = UNSET
    bearer: BearerInfoSchema | None | Unset = UNSET
    html_auto_form: HTMLAutoFormInfoSchema | None | Unset = UNSET
    html_form_based: HTMLFormBasedInfoSchema | None | Unset = UNSET
    http_basic: HTTPBasicInfoSchema | None | Unset = UNSET
    raw_cookie: None | RawCookieInfoSchema | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_key_info_schema import APIKeyInfoSchema
        from ..models.bearer_info_schema import BearerInfoSchema
        from ..models.html_auto_form_info_schema import HTMLAutoFormInfoSchema
        from ..models.html_form_based_info_schema import HTMLFormBasedInfoSchema
        from ..models.http_basic_info_schema import HTTPBasicInfoSchema
        from ..models.raw_cookie_info_schema import RawCookieInfoSchema

        group = self.group.to_dict()

        name = self.name

        type_ = self.type_.value

        api_key: dict[str, Any] | None | Unset
        if isinstance(self.api_key, Unset):
            api_key = UNSET
        elif isinstance(self.api_key, APIKeyInfoSchema):
            api_key = self.api_key.to_dict()
        else:
            api_key = self.api_key

        bearer: dict[str, Any] | None | Unset
        if isinstance(self.bearer, Unset):
            bearer = UNSET
        elif isinstance(self.bearer, BearerInfoSchema):
            bearer = self.bearer.to_dict()
        else:
            bearer = self.bearer

        html_auto_form: dict[str, Any] | None | Unset
        if isinstance(self.html_auto_form, Unset):
            html_auto_form = UNSET
        elif isinstance(self.html_auto_form, HTMLAutoFormInfoSchema):
            html_auto_form = self.html_auto_form.to_dict()
        else:
            html_auto_form = self.html_auto_form

        html_form_based: dict[str, Any] | None | Unset
        if isinstance(self.html_form_based, Unset):
            html_form_based = UNSET
        elif isinstance(self.html_form_based, HTMLFormBasedInfoSchema):
            html_form_based = self.html_form_based.to_dict()
        else:
            html_form_based = self.html_form_based

        http_basic: dict[str, Any] | None | Unset
        if isinstance(self.http_basic, Unset):
            http_basic = UNSET
        elif isinstance(self.http_basic, HTTPBasicInfoSchema):
            http_basic = self.http_basic.to_dict()
        else:
            http_basic = self.http_basic

        raw_cookie: dict[str, Any] | None | Unset
        if isinstance(self.raw_cookie, Unset):
            raw_cookie = UNSET
        elif isinstance(self.raw_cookie, RawCookieInfoSchema):
            raw_cookie = self.raw_cookie.to_dict()
        else:
            raw_cookie = self.raw_cookie

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'group': group,
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
        from ..models.api_key_info_schema import APIKeyInfoSchema
        from ..models.bearer_info_schema import BearerInfoSchema
        from ..models.group_short_info_schema import GroupShortInfoSchema
        from ..models.html_auto_form_info_schema import HTMLAutoFormInfoSchema
        from ..models.html_form_based_info_schema import HTMLFormBasedInfoSchema
        from ..models.http_basic_info_schema import HTTPBasicInfoSchema
        from ..models.raw_cookie_info_schema import RawCookieInfoSchema

        d = dict(src_dict)
        group = GroupShortInfoSchema.from_dict(d.pop('group'))

        name = d.pop('name')

        type_ = AuthenticationType(d.pop('type'))

        def _parse_api_key(data: object) -> APIKeyInfoSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                api_key_type_0 = APIKeyInfoSchema.from_dict(data)

                return api_key_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(APIKeyInfoSchema | None | Unset, data)

        api_key = _parse_api_key(d.pop('apiKey', UNSET))

        def _parse_bearer(data: object) -> BearerInfoSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                bearer_type_0 = BearerInfoSchema.from_dict(data)

                return bearer_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BearerInfoSchema | None | Unset, data)

        bearer = _parse_bearer(d.pop('bearer', UNSET))

        def _parse_html_auto_form(data: object) -> HTMLAutoFormInfoSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                html_auto_form_type_0 = HTMLAutoFormInfoSchema.from_dict(data)

                return html_auto_form_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HTMLAutoFormInfoSchema | None | Unset, data)

        html_auto_form = _parse_html_auto_form(d.pop('htmlAutoForm', UNSET))

        def _parse_html_form_based(data: object) -> HTMLFormBasedInfoSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                html_form_based_type_0 = HTMLFormBasedInfoSchema.from_dict(data)

                return html_form_based_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HTMLFormBasedInfoSchema | None | Unset, data)

        html_form_based = _parse_html_form_based(d.pop('htmlFormBased', UNSET))

        def _parse_http_basic(data: object) -> HTTPBasicInfoSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                http_basic_type_0 = HTTPBasicInfoSchema.from_dict(data)

                return http_basic_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(HTTPBasicInfoSchema | None | Unset, data)

        http_basic = _parse_http_basic(d.pop('httpBasic', UNSET))

        def _parse_raw_cookie(data: object) -> None | RawCookieInfoSchema | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                raw_cookie_type_0 = RawCookieInfoSchema.from_dict(data)

                return raw_cookie_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RawCookieInfoSchema | Unset, data)

        raw_cookie = _parse_raw_cookie(d.pop('rawCookie', UNSET))

        auth_profile_full_info_schema = cls(
            group=group,
            name=name,
            type_=type_,
            api_key=api_key,
            bearer=bearer,
            html_auto_form=html_auto_form,
            html_form_based=html_form_based,
            http_basic=http_basic,
            raw_cookie=raw_cookie,
        )

        auth_profile_full_info_schema.additional_properties = d
        return auth_profile_full_info_schema

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
