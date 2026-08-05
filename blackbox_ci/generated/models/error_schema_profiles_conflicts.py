from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.error_field_profiles_conflicts import ErrorFieldProfilesConflicts


T = TypeVar('T', bound='ErrorSchemaProfilesConflicts')


@_attrs_define
class ErrorSchemaProfilesConflicts:
    """
    Attributes:
        detail (str):
        error (ErrorFieldProfilesConflicts):
    """

    detail: str
    error: ErrorFieldProfilesConflicts
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        detail = self.detail

        error = self.error.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'detail': detail,
                'error': error,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_field_profiles_conflicts import ErrorFieldProfilesConflicts

        d = dict(src_dict)
        detail = d.pop('detail')

        error = ErrorFieldProfilesConflicts.from_dict(d.pop('error'))

        error_schema_profiles_conflicts = cls(
            detail=detail,
            error=error,
        )

        error_schema_profiles_conflicts.additional_properties = d
        return error_schema_profiles_conflicts

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
