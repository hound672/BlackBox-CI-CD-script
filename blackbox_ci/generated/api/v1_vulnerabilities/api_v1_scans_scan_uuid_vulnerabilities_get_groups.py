from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.severity import Severity
from ...models.vuln_group_schema import VulnGroupSchema
from ...types import UNSET, Response, Unset


def _get_kwargs(
    scan_uuid: UUID,
    *,
    severity: None | Severity | Unset = UNSET,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    params: dict[str, Any] = {}

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    elif isinstance(severity, Severity):
        json_severity = severity.value
    else:
        json_severity = severity
    params['severity'] = json_severity

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/scans/{scan_uuid}/vulnerabilities'.format(scan_uuid=quote(str(scan_uuid), safe='')),
        'params': params,
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = VulnGroupSchema.from_dict(response_200_item_data)

            response_200.append(response_200_item)

        return response_200

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: None | Severity | Unset = UNSET,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]]:
    """GetGroups

    Args:
        scan_uuid (UUID):
        severity (None | Severity | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        severity=severity,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: None | Severity | Unset = UNSET,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema] | None:
    """GetGroups

    Args:
        scan_uuid (UUID):
        severity (None | Severity | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]
    """

    return sync_detailed(
        scan_uuid=scan_uuid,
        client=client,
        severity=severity,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: None | Severity | Unset = UNSET,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]]:
    """GetGroups

    Args:
        scan_uuid (UUID):
        severity (None | Severity | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        severity=severity,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: None | Severity | Unset = UNSET,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema] | None:
    """GetGroups

    Args:
        scan_uuid (UUID):
        severity (None | Severity | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | list[VulnGroupSchema]
    """

    return (
        await asyncio_detailed(
            scan_uuid=scan_uuid,
            client=client,
            severity=severity,
            authorization=authorization,
        )
    ).parsed
