from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar('T', bound='ProfileCloneSchema')


@_attrs_define
class ProfileCloneSchema:
    """
    Attributes:
        group_uuid (None | Unset | UUID):
    """

    group_uuid: None | Unset | UUID = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group_uuid: None | str | Unset
        if isinstance(self.group_uuid, Unset):
            group_uuid = UNSET
        elif isinstance(self.group_uuid, UUID):
            group_uuid = str(self.group_uuid)
        else:
            group_uuid = self.group_uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if group_uuid is not UNSET:
            field_dict['groupUUID'] = group_uuid

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_group_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                group_uuid_type_0 = UUID(data)

                return group_uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        group_uuid = _parse_group_uuid(d.pop('groupUUID', UNSET))

        profile_clone_schema = cls(
            group_uuid=group_uuid,
        )

        profile_clone_schema.additional_properties = d
        return profile_clone_schema

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
