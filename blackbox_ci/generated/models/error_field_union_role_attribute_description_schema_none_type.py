from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.role_attribute_description_schema import RoleAttributeDescriptionSchema


T = TypeVar('T', bound='ErrorFieldUnionRoleAttributeDescriptionSchemaNoneType')


@_attrs_define
class ErrorFieldUnionRoleAttributeDescriptionSchemaNoneType:
    """
    Attributes:
        code (str):
        description (None | str | Unset):
        details (None | RoleAttributeDescriptionSchema | Unset):
    """

    code: str
    description: None | str | Unset = UNSET
    details: None | RoleAttributeDescriptionSchema | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.role_attribute_description_schema import RoleAttributeDescriptionSchema

        code = self.code

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        details: dict[str, Any] | None | Unset
        if isinstance(self.details, Unset):
            details = UNSET
        elif isinstance(self.details, RoleAttributeDescriptionSchema):
            details = self.details.to_dict()
        else:
            details = self.details

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'code': code,
            }
        )
        if description is not UNSET:
            field_dict['description'] = description
        if details is not UNSET:
            field_dict['details'] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.role_attribute_description_schema import RoleAttributeDescriptionSchema

        d = dict(src_dict)
        code = d.pop('code')

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop('description', UNSET))

        def _parse_details(data: object) -> None | RoleAttributeDescriptionSchema | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                details_type_0 = RoleAttributeDescriptionSchema.from_dict(data)

                return details_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RoleAttributeDescriptionSchema | Unset, data)

        details = _parse_details(d.pop('details', UNSET))

        error_field_union_role_attribute_description_schema_none_type = cls(
            code=code,
            description=description,
            details=details,
        )

        error_field_union_role_attribute_description_schema_none_type.additional_properties = d
        return error_field_union_role_attribute_description_schema_none_type

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
