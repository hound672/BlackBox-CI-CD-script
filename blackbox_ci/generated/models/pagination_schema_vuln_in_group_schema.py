from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vuln_cve_schema import VulnCVESchema
    from ..models.vuln_error_page_schema import VulnErrorPageSchema
    from ..models.vuln_trending_schema import VulnTrendingSchema
    from ..models.vuln_we_schema import VulnWESchema


T = TypeVar('T', bound='PaginationSchemaVulnInGroupSchema')


@_attrs_define
class PaginationSchemaVulnInGroupSchema:
    """
    Attributes:
        current_page (int):
        items (list[VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema | VulnWESchema]):
        total_count (int):
        total_items (int):
    """

    current_page: int
    items: list[VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema | VulnWESchema]
    total_count: int
    total_items: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.vuln_cve_schema import VulnCVESchema
        from ..models.vuln_error_page_schema import VulnErrorPageSchema
        from ..models.vuln_we_schema import VulnWESchema

        current_page = self.current_page

        items = []
        for items_item_data in self.items:
            items_item: dict[str, Any]
            if (
                isinstance(items_item_data, VulnWESchema)
                or isinstance(items_item_data, VulnCVESchema)
                or isinstance(items_item_data, VulnErrorPageSchema)
            ):
                items_item = items_item_data.to_dict()
            else:
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
        from ..models.vuln_cve_schema import VulnCVESchema
        from ..models.vuln_error_page_schema import VulnErrorPageSchema
        from ..models.vuln_trending_schema import VulnTrendingSchema
        from ..models.vuln_we_schema import VulnWESchema

        d = dict(src_dict)
        current_page = d.pop('currentPage')

        items = []
        _items = d.pop('items')
        for items_item_data in _items:

            def _parse_items_item(
                data: object,
            ) -> VulnCVESchema | VulnErrorPageSchema | VulnTrendingSchema | VulnWESchema:
                try:
                    if not isinstance(data, dict):
                        raise TypeError
                    items_item_type_0 = VulnWESchema.from_dict(data)

                    return items_item_type_0
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError
                    items_item_type_1 = VulnCVESchema.from_dict(data)

                    return items_item_type_1
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                try:
                    if not isinstance(data, dict):
                        raise TypeError
                    items_item_type_2 = VulnErrorPageSchema.from_dict(data)

                    return items_item_type_2
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass
                if not isinstance(data, dict):
                    raise TypeError
                items_item_type_3 = VulnTrendingSchema.from_dict(data)

                return items_item_type_3

            items_item = _parse_items_item(items_item_data)

            items.append(items_item)

        total_count = d.pop('totalCount')

        total_items = d.pop('totalItems')

        pagination_schema_vuln_in_group_schema = cls(
            current_page=current_page,
            items=items,
            total_count=total_count,
            total_items=total_items,
        )

        pagination_schema_vuln_in_group_schema.additional_properties = d
        return pagination_schema_vuln_in_group_schema

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
