from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_union_role_attribute_description_schema_none_type import (
    ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType,
)
from ...models.scan_queue_profiles_schema import ScanQueueProfilesSchema
from ...types import Response


def _get_kwargs(
    site_uuid: UUID,
    *,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/sites/{site_uuid}/start'.format(site_uuid=quote(str(site_uuid), safe='')),
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema | None:
    if response.status_code == 202:
        response_202 = ScanQueueProfilesSchema.from_dict(response.json())

        return response_202

    if response.status_code == 403:
        response_403 = ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if response.status_code == 503:
        response_503 = ErrorSchemaNoneType.from_dict(response.json())

        return response_503

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema]:
    """Start

    Args:
        site_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema]
    """

    kwargs = _get_kwargs(
        site_uuid=site_uuid,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema | None:
    """Start

    Args:
        site_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema
    """

    return sync_detailed(
        site_uuid=site_uuid,
        client=client,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema]:
    """Start

    Args:
        site_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema]
    """

    kwargs = _get_kwargs(
        site_uuid=site_uuid,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema | None:
    """Start

    Args:
        site_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaUnionRoleAttributeDescriptionSchemaNoneType | ScanQueueProfilesSchema
    """

    return (
        await asyncio_detailed(
            site_uuid=site_uuid,
            client=client,
            authorization=authorization,
        )
    ).parsed
