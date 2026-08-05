from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.api_schema_types import APISchemaTypes
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.api_schema_har_options_schema import APISchemaHAROptionsSchema
    from ..models.api_schema_open_api_options_schema import APISchemaOpenAPIOptionsSchema
    from ..models.api_schema_short_content_schema import APISchemaShortContentSchema


T = TypeVar('T', bound='APISchemaShortSchema')


@_attrs_define
class APISchemaShortSchema:
    """
    Attributes:
        content (APISchemaShortContentSchema):
        name (str):
        type_ (APISchemaTypes):
        uuid (str):
        har_options (APISchemaHAROptionsSchema | None | Unset):
        openapi_options (APISchemaOpenAPIOptionsSchema | None | Unset):
    """

    content: APISchemaShortContentSchema
    name: str
    type_: APISchemaTypes
    uuid: str
    har_options: APISchemaHAROptionsSchema | None | Unset = UNSET
    openapi_options: APISchemaOpenAPIOptionsSchema | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_schema_har_options_schema import APISchemaHAROptionsSchema
        from ..models.api_schema_open_api_options_schema import APISchemaOpenAPIOptionsSchema

        content = self.content.to_dict()

        name = self.name

        type_ = self.type_.value

        uuid = self.uuid

        har_options: dict[str, Any] | None | Unset
        if isinstance(self.har_options, Unset):
            har_options = UNSET
        elif isinstance(self.har_options, APISchemaHAROptionsSchema):
            har_options = self.har_options.to_dict()
        else:
            har_options = self.har_options

        openapi_options: dict[str, Any] | None | Unset
        if isinstance(self.openapi_options, Unset):
            openapi_options = UNSET
        elif isinstance(self.openapi_options, APISchemaOpenAPIOptionsSchema):
            openapi_options = self.openapi_options.to_dict()
        else:
            openapi_options = self.openapi_options

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'content': content,
                'name': name,
                'type': type_,
                'uuid': uuid,
            }
        )
        if har_options is not UNSET:
            field_dict['harOptions'] = har_options
        if openapi_options is not UNSET:
            field_dict['openapiOptions'] = openapi_options

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_schema_har_options_schema import APISchemaHAROptionsSchema
        from ..models.api_schema_open_api_options_schema import APISchemaOpenAPIOptionsSchema
        from ..models.api_schema_short_content_schema import APISchemaShortContentSchema

        d = dict(src_dict)
        content = APISchemaShortContentSchema.from_dict(d.pop('content'))

        name = d.pop('name')

        type_ = APISchemaTypes(d.pop('type'))

        uuid = d.pop('uuid')

        def _parse_har_options(data: object) -> APISchemaHAROptionsSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                har_options_type_0 = APISchemaHAROptionsSchema.from_dict(data)

                return har_options_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(APISchemaHAROptionsSchema | None | Unset, data)

        har_options = _parse_har_options(d.pop('harOptions', UNSET))

        def _parse_openapi_options(data: object) -> APISchemaOpenAPIOptionsSchema | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                openapi_options_type_0 = APISchemaOpenAPIOptionsSchema.from_dict(data)

                return openapi_options_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(APISchemaOpenAPIOptionsSchema | None | Unset, data)

        openapi_options = _parse_openapi_options(d.pop('openapiOptions', UNSET))

        api_schema_short_schema = cls(
            content=content,
            name=name,
            type_=type_,
            uuid=uuid,
            har_options=har_options,
            openapi_options=openapi_options,
        )

        api_schema_short_schema.additional_properties = d
        return api_schema_short_schema

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
