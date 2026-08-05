from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.group_short_info_schema import GroupShortInfoSchema


T = TypeVar('T', bound='APIProfileShortInfoSchema')


@_attrs_define
class APIProfileShortInfoSchema:
    """
    Attributes:
        count_of_schemas (int):
        name (str):
        uuid (str):
        group (GroupShortInfoSchema | None | Unset):
    """

    count_of_schemas: int
    name: str
    uuid: str
    group: GroupShortInfoSchema | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.group_short_info_schema import GroupShortInfoSchema

        count_of_schemas = self.count_of_schemas

        name = self.name

        uuid = self.uuid

        group: dict[str, Any] | None | Unset
        if isinstance(self.group, Unset):
            group = UNSET
        elif isinstance(self.group, GroupShortInfoSchema):
            group = self.group.to_dict()
        else:
            group = self.group

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'countOfSchemas': count_of_schemas,
                'name': name,
                'uuid': uuid,
            }
        )
        if group is not UNSET:
            field_dict['group'] = group

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.group_short_info_schema import GroupShortInfoSchema

        d = dict(src_dict)
        count_of_schemas = d.pop('countOfSchemas')

        name = d.pop('name')

        uuid = d.pop('uuid')

        def _parse_group(data: object) -> GroupShortInfoSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                group_type_0 = GroupShortInfoSchema.from_dict(data)

                return group_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GroupShortInfoSchema | None | Unset, data)

        group = _parse_group(d.pop('group', UNSET))

        api_profile_short_info_schema = cls(
            count_of_schemas=count_of_schemas,
            name=name,
            uuid=uuid,
            group=group,
        )

        api_profile_short_info_schema.additional_properties = d
        return api_profile_short_info_schema

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
