from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.group_role_full_info_schema import GroupRoleFullInfoSchema
from ...types import Response


def _get_kwargs(
    group_uuid: UUID,
    *,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/groups/{group_uuid}'.format(group_uuid=quote(str(group_uuid), safe='')),
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | GroupRoleFullInfoSchema | None:
    if response.status_code == 200:
        response_200 = GroupRoleFullInfoSchema.from_dict(response.json())

        return response_200

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorSchemaNoneType | GroupRoleFullInfoSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    group_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[ErrorSchemaNoneType | GroupRoleFullInfoSchema]:
    """Get

    Args:
        group_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | GroupRoleFullInfoSchema]
    """

    kwargs = _get_kwargs(
        group_uuid=group_uuid,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    group_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> ErrorSchemaNoneType | GroupRoleFullInfoSchema | None:
    """Get

    Args:
        group_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | GroupRoleFullInfoSchema
    """

    return sync_detailed(
        group_uuid=group_uuid,
        client=client,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    group_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[ErrorSchemaNoneType | GroupRoleFullInfoSchema]:
    """Get

    Args:
        group_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | GroupRoleFullInfoSchema]
    """

    kwargs = _get_kwargs(
        group_uuid=group_uuid,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    group_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> ErrorSchemaNoneType | GroupRoleFullInfoSchema | None:
    """Get

    Args:
        group_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | GroupRoleFullInfoSchema
    """

    return (
        await asyncio_detailed(
            group_uuid=group_uuid,
            client=client,
            authorization=authorization,
        )
    ).parsed
