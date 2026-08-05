from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.auth_chain_short_info_schema import AuthChainShortInfoSchema
from ...models.auth_chain_update_schema import AuthChainUpdateSchema
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...types import Response


def _get_kwargs(
    auth_chain_uuid: UUID,
    *,
    body: AuthChainUpdateSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'patch',
        'url': '/api/v1/auth-chains/{auth_chain_uuid}'.format(auth_chain_uuid=quote(str(auth_chain_uuid), safe='')),
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AuthChainShortInfoSchema | ErrorSchemaNoneType | None:
    if response.status_code == 200:
        response_200 = AuthChainShortInfoSchema.from_dict(response.json())

        return response_200

    if response.status_code == 403:
        response_403 = ErrorSchemaNoneType.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if response.status_code == 409:
        response_409 = ErrorSchemaNoneType.from_dict(response.json())

        return response_409

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AuthChainShortInfoSchema | ErrorSchemaNoneType]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    auth_chain_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthChainUpdateSchema,
    authorization: str,
) -> Response[AuthChainShortInfoSchema | ErrorSchemaNoneType]:
    """Update

    Args:
        auth_chain_uuid (UUID):
        authorization (str):
        body (AuthChainUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthChainShortInfoSchema | ErrorSchemaNoneType]
    """

    kwargs = _get_kwargs(
        auth_chain_uuid=auth_chain_uuid,
        body=body,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    auth_chain_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthChainUpdateSchema,
    authorization: str,
) -> AuthChainShortInfoSchema | ErrorSchemaNoneType | None:
    """Update

    Args:
        auth_chain_uuid (UUID):
        authorization (str):
        body (AuthChainUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthChainShortInfoSchema | ErrorSchemaNoneType
    """

    return sync_detailed(
        auth_chain_uuid=auth_chain_uuid,
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    auth_chain_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthChainUpdateSchema,
    authorization: str,
) -> Response[AuthChainShortInfoSchema | ErrorSchemaNoneType]:
    """Update

    Args:
        auth_chain_uuid (UUID):
        authorization (str):
        body (AuthChainUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthChainShortInfoSchema | ErrorSchemaNoneType]
    """

    kwargs = _get_kwargs(
        auth_chain_uuid=auth_chain_uuid,
        body=body,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    auth_chain_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthChainUpdateSchema,
    authorization: str,
) -> AuthChainShortInfoSchema | ErrorSchemaNoneType | None:
    """Update

    Args:
        auth_chain_uuid (UUID):
        authorization (str):
        body (AuthChainUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthChainShortInfoSchema | ErrorSchemaNoneType
    """

    return (
        await asyncio_detailed(
            auth_chain_uuid=auth_chain_uuid,
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
