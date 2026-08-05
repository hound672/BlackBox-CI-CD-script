from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.shared_link_create_schema import SharedLinkCreateSchema
from ...models.shared_link_schema import SharedLinkSchema
from ...types import Response


def _get_kwargs(
    scan_uuid: UUID,
    *,
    body: SharedLinkCreateSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/scans/{scan_uuid}/shared'.format(scan_uuid=quote(str(scan_uuid), safe='')),
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema | None:
    if response.status_code == 201:
        response_201 = SharedLinkSchema.from_dict(response.json())

        return response_201

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
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema]:
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
    body: SharedLinkCreateSchema,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema]:
    """Create

    Args:
        scan_uuid (UUID):
        authorization (str):
        body (SharedLinkCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        body=body,
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
    body: SharedLinkCreateSchema,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema | None:
    """Create

    Args:
        scan_uuid (UUID):
        authorization (str):
        body (SharedLinkCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema
    """

    return sync_detailed(
        scan_uuid=scan_uuid,
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: SharedLinkCreateSchema,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema]:
    """Create

    Args:
        scan_uuid (UUID):
        authorization (str):
        body (SharedLinkCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        body=body,
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
    body: SharedLinkCreateSchema,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema | None:
    """Create

    Args:
        scan_uuid (UUID):
        authorization (str):
        body (SharedLinkCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SharedLinkSchema
    """

    return (
        await asyncio_detailed(
            scan_uuid=scan_uuid,
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
