from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.shared_link_schema import SharedLinkSchema
from ...types import Response


def _get_kwargs(
    scan_uuid: UUID,
    *,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/scans/{scan_uuid}/shared'.format(scan_uuid=quote(str(scan_uuid), safe='')),
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | list[SharedLinkSchema] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = SharedLinkSchema.from_dict(response_200_item_data)

            response_200.append(response_200_item)

        return response_200

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorSchemaNoneType | list[SharedLinkSchema]]:
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
    authorization: str,
) -> Response[ErrorSchemaNoneType | list[SharedLinkSchema]]:
    """GetAll

    Args:
        scan_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | list[SharedLinkSchema]]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
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
    authorization: str,
) -> ErrorSchemaNoneType | list[SharedLinkSchema] | None:
    """GetAll

    Args:
        scan_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | list[SharedLinkSchema]
    """

    return sync_detailed(
        scan_uuid=scan_uuid,
        client=client,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[ErrorSchemaNoneType | list[SharedLinkSchema]]:
    """GetAll

    Args:
        scan_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | list[SharedLinkSchema]]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
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
    authorization: str,
) -> ErrorSchemaNoneType | list[SharedLinkSchema] | None:
    """GetAll

    Args:
        scan_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | list[SharedLinkSchema]
    """

    return (
        await asyncio_detailed(
            scan_uuid=scan_uuid,
            client=client,
            authorization=authorization,
        )
    ).parsed
