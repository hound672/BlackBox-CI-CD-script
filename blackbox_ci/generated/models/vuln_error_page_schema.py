from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

if TYPE_CHECKING:
    from ..models.vuln_error_page_schema_request import VulnErrorPageSchemaRequest
    from ..models.vuln_error_page_schema_response_type_0 import VulnErrorPageSchemaResponseType0


T = TypeVar('T', bound='VulnErrorPageSchema')


@_attrs_define
class VulnErrorPageSchema:
    """
    Attributes:
        code (int):
        request (VulnErrorPageSchemaRequest):
        response (None | VulnErrorPageSchemaResponseType0):
        type_ (Literal['error_page']):
        url (str):
        uuid (str):
    """

    code: int
    request: VulnErrorPageSchemaRequest
    response: None | VulnErrorPageSchemaResponseType0
    type_: Literal['error_page']
    url: str
    uuid: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.vuln_error_page_schema_response_type_0 import VulnErrorPageSchemaResponseType0

        code = self.code

        request = self.request.to_dict()

        response: dict[str, Any] | None
        if isinstance(self.response, VulnErrorPageSchemaResponseType0):
            response = self.response.to_dict()
        else:
            response = self.response

        type_ = self.type_

        url = self.url

        uuid = self.uuid

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                'code': code,
                'request': request,
                'response': response,
                'type': type_,
                'url': url,
                'uuid': uuid,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_error_page_schema_request import VulnErrorPageSchemaRequest
        from ..models.vuln_error_page_schema_response_type_0 import VulnErrorPageSchemaResponseType0

        d = dict(src_dict)
        code = d.pop('code')

        request = VulnErrorPageSchemaRequest.from_dict(d.pop('request'))

        def _parse_response(data: object) -> None | VulnErrorPageSchemaResponseType0:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                response_type_0 = VulnErrorPageSchemaResponseType0.from_dict(data)

                return response_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | VulnErrorPageSchemaResponseType0, data)

        response = _parse_response(d.pop('response'))

        type_ = cast(Literal['error_page'], d.pop('type'))
        if type_ != 'error_page':
            raise ValueError(f"type must match const 'error_page', got '{type_}'")

        url = d.pop('url')

        uuid = d.pop('uuid')

        vuln_error_page_schema = cls(
            code=code,
            request=request,
            response=response,
            type_=type_,
            url=url,
            uuid=uuid,
        )

        vuln_error_page_schema.additional_properties = d
        return vuln_error_page_schema

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
