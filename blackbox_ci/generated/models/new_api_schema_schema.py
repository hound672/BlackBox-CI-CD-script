from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from ..models.api_schema_types import APISchemaTypes
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.api_schema_har_options_schema import APISchemaHAROptionsSchema
    from ..models.api_schema_open_api_options_schema import APISchemaOpenAPIOptionsSchema


T = TypeVar('T', bound='NewAPISchemaSchema')


@_attrs_define
class NewAPISchemaSchema:
    """
    Attributes:
        group_uuid (UUID):
        type_ (APISchemaTypes):
        file_uuid (None | Unset | UUID):
        har_options (APISchemaHAROptionsSchema | None | Unset):
        link (None | str | Unset):
        name (None | str | Unset):
        openapi_options (APISchemaOpenAPIOptionsSchema | None | Unset):
    """

    group_uuid: UUID
    type_: APISchemaTypes
    file_uuid: None | Unset | UUID = UNSET
    har_options: APISchemaHAROptionsSchema | None | Unset = UNSET
    link: None | str | Unset = UNSET
    name: None | str | Unset = UNSET
    openapi_options: APISchemaOpenAPIOptionsSchema | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.api_schema_har_options_schema import APISchemaHAROptionsSchema
        from ..models.api_schema_open_api_options_schema import APISchemaOpenAPIOptionsSchema

        group_uuid = str(self.group_uuid)

        type_ = self.type_.value

        file_uuid: None | str | Unset
        if isinstance(self.file_uuid, Unset):
            file_uuid = UNSET
        elif isinstance(self.file_uuid, UUID):
            file_uuid = str(self.file_uuid)
        else:
            file_uuid = self.file_uuid

        har_options: dict[str, Any] | None | Unset
        if isinstance(self.har_options, Unset):
            har_options = UNSET
        elif isinstance(self.har_options, APISchemaHAROptionsSchema):
            har_options = self.har_options.to_dict()
        else:
            har_options = self.har_options

        link: None | str | Unset
        if isinstance(self.link, Unset):
            link = UNSET
        else:
            link = self.link

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

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
                'groupUUID': group_uuid,
                'type': type_,
            }
        )
        if file_uuid is not UNSET:
            field_dict['fileUuid'] = file_uuid
        if har_options is not UNSET:
            field_dict['harOptions'] = har_options
        if link is not UNSET:
            field_dict['link'] = link
        if name is not UNSET:
            field_dict['name'] = name
        if openapi_options is not UNSET:
            field_dict['openapiOptions'] = openapi_options

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.api_schema_har_options_schema import APISchemaHAROptionsSchema
        from ..models.api_schema_open_api_options_schema import APISchemaOpenAPIOptionsSchema

        d = dict(src_dict)
        group_uuid = UUID(d.pop('groupUUID'))

        type_ = APISchemaTypes(d.pop('type'))

        def _parse_file_uuid(data: object) -> None | Unset | UUID:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                file_uuid_type_0 = UUID(data)

                return file_uuid_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UUID, data)

        file_uuid = _parse_file_uuid(d.pop('fileUuid', UNSET))

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

        def _parse_link(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        link = _parse_link(d.pop('link', UNSET))

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop('name', UNSET))

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

        new_api_schema_schema = cls(
            group_uuid=group_uuid,
            type_=type_,
            file_uuid=file_uuid,
            har_options=har_options,
            link=link,
            name=name,
            openapi_options=openapi_options,
        )

        new_api_schema_schema.additional_properties = d
        return new_api_schema_schema

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
