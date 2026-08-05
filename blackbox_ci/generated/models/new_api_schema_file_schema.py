from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar
from uuid import UUID

from attrs import define as _attrs_define, field as _attrs_field

from .. import types
from ..types import File

T = TypeVar('T', bound='NewAPISchemaFileSchema')


@_attrs_define
class NewAPISchemaFileSchema:
    """
    Attributes:
        file (File):
        group_uuid (UUID):
    """

    file: File
    group_uuid: UUID
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file = self.file.to_tuple()

        group_uuid = str(self.group_uuid)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'file': file,
                'groupUUID': group_uuid,
            }
        )

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        files.append(('file', self.file.to_tuple()))

        files.append(('groupUUID', (None, str(self.group_uuid), 'text/plain')))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), 'text/plain')))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file = File(
            payload=BytesIO(d.pop('file')),
        )

        group_uuid = UUID(d.pop('groupUUID'))

        new_api_schema_file_schema = cls(
            file=file,
            group_uuid=group_uuid,
        )

        new_api_schema_file_schema.additional_properties = d
        return new_api_schema_file_schema

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
