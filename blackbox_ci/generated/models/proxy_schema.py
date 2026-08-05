from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.proxy_type import ProxyType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.proxy_auth_schema import ProxyAuthSchema


T = TypeVar('T', bound='ProxySchema')


@_attrs_define
class ProxySchema:
    """
    Attributes:
        host (str):
        port (int):
        type_ (ProxyType):
        auth (None | ProxyAuthSchema | Unset):
    """

    host: str
    port: int
    type_: ProxyType
    auth: None | ProxyAuthSchema | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.proxy_auth_schema import ProxyAuthSchema

        host = self.host

        port = self.port

        type_ = self.type_.value

        auth: dict[str, Any] | None | Unset
        if isinstance(self.auth, Unset):
            auth = UNSET
        elif isinstance(self.auth, ProxyAuthSchema):
            auth = self.auth.to_dict()
        else:
            auth = self.auth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'host': host,
                'port': port,
                'type': type_,
            }
        )
        if auth is not UNSET:
            field_dict['auth'] = auth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.proxy_auth_schema import ProxyAuthSchema

        d = dict(src_dict)
        host = d.pop('host')

        port = d.pop('port')

        type_ = ProxyType(d.pop('type'))

        def _parse_auth(data: object) -> None | ProxyAuthSchema | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                auth_type_0 = ProxyAuthSchema.from_dict(data)

                return auth_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ProxyAuthSchema | Unset, data)

        auth = _parse_auth(d.pop('auth', UNSET))

        proxy_schema = cls(
            host=host,
            port=port,
            type_=type_,
            auth=auth,
        )

        proxy_schema.additional_properties = d
        return proxy_schema

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
