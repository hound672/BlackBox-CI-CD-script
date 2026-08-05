from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.api_schema_full_schema import APISchemaFullSchema
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...types import Response


def _get_kwargs(
    schema_uuid: UUID,
    *,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/api-profiles/schema/{schema_uuid}'.format(schema_uuid=quote(str(schema_uuid), safe='')),
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> APISchemaFullSchema | ErrorSchemaNoneType | None:
    if response.status_code == 200:
        response_200 = APISchemaFullSchema.from_dict(response.json())

        return response_200

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[APISchemaFullSchema | ErrorSchemaNoneType]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    schema_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[APISchemaFullSchema | ErrorSchemaNoneType]:
    """GetSchema

    Args:
        schema_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APISchemaFullSchema | ErrorSchemaNoneType]
    """

    kwargs = _get_kwargs(
        schema_uuid=schema_uuid,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    schema_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> APISchemaFullSchema | ErrorSchemaNoneType | None:
    """GetSchema

    Args:
        schema_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APISchemaFullSchema | ErrorSchemaNoneType
    """

    return sync_detailed(
        schema_uuid=schema_uuid,
        client=client,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    schema_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[APISchemaFullSchema | ErrorSchemaNoneType]:
    """GetSchema

    Args:
        schema_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APISchemaFullSchema | ErrorSchemaNoneType]
    """

    kwargs = _get_kwargs(
        schema_uuid=schema_uuid,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    schema_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> APISchemaFullSchema | ErrorSchemaNoneType | None:
    """GetSchema

    Args:
        schema_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APISchemaFullSchema | ErrorSchemaNoneType
    """

    return (
        await asyncio_detailed(
            schema_uuid=schema_uuid,
            client=client,
            authorization=authorization,
        )
    ).parsed
