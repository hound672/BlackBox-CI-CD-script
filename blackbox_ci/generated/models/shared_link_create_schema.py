from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.shared_link_ttl import SharedLinkTTL
from ..types import UNSET, Unset

T = TypeVar('T', bound='SharedLinkCreateSchema')


@_attrs_define
class SharedLinkCreateSchema:
    """
    Attributes:
        emails (list[str] | None | Unset):
        ttl (None | SharedLinkTTL | Unset):
    """

    emails: list[str] | None | Unset = UNSET
    ttl: None | SharedLinkTTL | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        emails: list[str] | None | Unset
        if isinstance(self.emails, Unset):
            emails = UNSET
        elif isinstance(self.emails, list):
            emails = self.emails

        else:
            emails = self.emails

        ttl: int | None | Unset
        if isinstance(self.ttl, Unset):
            ttl = UNSET
        elif isinstance(self.ttl, SharedLinkTTL):
            ttl = self.ttl.value
        else:
            ttl = self.ttl

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if emails is not UNSET:
            field_dict['emails'] = emails
        if ttl is not UNSET:
            field_dict['ttl'] = ttl

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_emails(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                emails_type_0 = cast(list[str], data)

                return emails_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        emails = _parse_emails(d.pop('emails', UNSET))

        def _parse_ttl(data: object) -> None | SharedLinkTTL | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, int):
                    raise TypeError
                ttl_type_0 = SharedLinkTTL(data)

                return ttl_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SharedLinkTTL | Unset, data)

        ttl = _parse_ttl(d.pop('ttl', UNSET))

        shared_link_create_schema = cls(
            emails=emails,
            ttl=ttl,
        )

        shared_link_create_schema.additional_properties = d
        return shared_link_create_schema

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
