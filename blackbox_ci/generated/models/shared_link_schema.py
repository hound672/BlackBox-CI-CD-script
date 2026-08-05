from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar('T', bound='SharedLinkSchema')


@_attrs_define
class SharedLinkSchema:
    """
    Attributes:
        emails (list[str] | None):
        uuid (str):
        valid_to (datetime.datetime | None):
    """

    emails: list[str] | None
    uuid: str
    valid_to: datetime.datetime | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        emails: list[str] | None
        if isinstance(self.emails, list):
            emails = self.emails

        else:
            emails = self.emails

        uuid = self.uuid

        valid_to: None | str
        if isinstance(self.valid_to, datetime.datetime):
            valid_to = self.valid_to.isoformat()
        else:
            valid_to = self.valid_to

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'emails': emails,
                'uuid': uuid,
                'validTo': valid_to,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_emails(data: object) -> list[str] | None:
            if data is None:
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                emails_type_0 = cast(list[str], data)

                return emails_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None, data)

        emails = _parse_emails(d.pop('emails'))

        uuid = d.pop('uuid')

        def _parse_valid_to(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                valid_to_type_0 = isoparse(data)

                return valid_to_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        valid_to = _parse_valid_to(d.pop('validTo'))

        shared_link_schema = cls(
            emails=emails,
            uuid=uuid,
            valid_to=valid_to,
        )

        shared_link_schema.additional_properties = d
        return shared_link_schema

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
