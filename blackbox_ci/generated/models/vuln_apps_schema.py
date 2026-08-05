from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vuln_app_schema import VulnAppSchema


T = TypeVar('T', bound='VulnAppsSchema')


@_attrs_define
class VulnAppsSchema:
    """
    Attributes:
        apps (list[VulnAppSchema]):
        type_ (Literal['apps']):
    """

    apps: list[VulnAppSchema]
    type_: Literal['apps']
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        apps = []
        for apps_item_data in self.apps:
            apps_item = apps_item_data.to_dict()
            apps.append(apps_item)

        type_ = self.type_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'apps': apps,
                'type': type_,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_app_schema import VulnAppSchema

        d = dict(src_dict)
        apps = []
        _apps = d.pop('apps')
        for apps_item_data in _apps:
            apps_item = VulnAppSchema.from_dict(apps_item_data)

            apps.append(apps_item)

        type_ = cast(Literal['apps'], d.pop('type'))
        if type_ != 'apps':
            raise ValueError(f"type must match const 'apps', got '{type_}'")

        vuln_apps_schema = cls(
            apps=apps,
            type_=type_,
        )

        vuln_apps_schema.additional_properties = d
        return vuln_apps_schema

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
