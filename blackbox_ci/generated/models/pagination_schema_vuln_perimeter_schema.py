from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vuln_perimeter_schema import VulnPerimeterSchema


T = TypeVar('T', bound='PaginationSchemaVulnPerimeterSchema')


@_attrs_define
class PaginationSchemaVulnPerimeterSchema:
    """
    Attributes:
        current_page (int):
        items (list[VulnPerimeterSchema]):
        total_count (int):
        total_items (int):
    """

    current_page: int
    items: list[VulnPerimeterSchema]
    total_count: int
    total_items: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        current_page = self.current_page

        items = []
        for items_item_data in self.items:
            items_item = items_item_data.to_dict()
            items.append(items_item)

        total_count = self.total_count

        total_items = self.total_items

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'currentPage': current_page,
                'items': items,
                'totalCount': total_count,
                'totalItems': total_items,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_perimeter_schema import VulnPerimeterSchema

        d = dict(src_dict)
        current_page = d.pop('currentPage')

        items = []
        _items = d.pop('items')
        for items_item_data in _items:
            items_item = VulnPerimeterSchema.from_dict(items_item_data)

            items.append(items_item)

        total_count = d.pop('totalCount')

        total_items = d.pop('totalItems')

        pagination_schema_vuln_perimeter_schema = cls(
            current_page=current_page,
            items=items,
            total_count=total_count,
            total_items=total_items,
        )

        pagination_schema_vuln_perimeter_schema.additional_properties = d
        return pagination_schema_vuln_perimeter_schema

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
