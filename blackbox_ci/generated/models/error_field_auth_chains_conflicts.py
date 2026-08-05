from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auth_chains_conflicts import AuthChainsConflicts


T = TypeVar('T', bound='ErrorFieldAuthChainsConflicts')


@_attrs_define
class ErrorFieldAuthChainsConflicts:
    """
    Attributes:
        code (str):
        details (AuthChainsConflicts):
        description (None | str | Unset):
    """

    code: str
    details: AuthChainsConflicts
    description: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        code = self.code

        details = self.details.to_dict()

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'code': code,
                'details': details,
            }
        )
        if description is not UNSET:
            field_dict['description'] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auth_chains_conflicts import AuthChainsConflicts

        d = dict(src_dict)
        code = d.pop('code')

        details = AuthChainsConflicts.from_dict(d.pop('details'))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop('description', UNSET))

        error_field_auth_chains_conflicts = cls(
            code=code,
            details=details,
            description=description,
        )

        error_field_auth_chains_conflicts.additional_properties = d
        return error_field_auth_chains_conflicts

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
