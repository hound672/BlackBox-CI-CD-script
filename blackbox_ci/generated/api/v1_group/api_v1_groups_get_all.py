from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.group_role_info_schema import GroupRoleInfoSchema
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    by_name: None | str | Unset = UNSET,
    by_role: None | str | Unset = UNSET,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    params: dict[str, Any] = {}

    json_by_name: None | str | Unset
    if isinstance(by_name, Unset):
        json_by_name = UNSET
    else:
        json_by_name = by_name
    params['by_name'] = json_by_name

    json_by_role: None | str | Unset
    if isinstance(by_role, Unset):
        json_by_role = UNSET
    else:
        json_by_role = by_role
    params['by_role'] = json_by_role

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/groups',
        'params': params,
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> list[GroupRoleInfoSchema] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GroupRoleInfoSchema.from_dict(response_200_item_data)

            response_200.append(response_200_item)

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[list[GroupRoleInfoSchema]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    by_name: None | str | Unset = UNSET,
    by_role: None | str | Unset = UNSET,
    authorization: str,
) -> Response[list[GroupRoleInfoSchema]]:
    """GetAll

    Args:
        by_name (None | str | Unset):
        by_role (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[list[GroupRoleInfoSchema]]
    """

    kwargs = _get_kwargs(
        by_name=by_name,
        by_role=by_role,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    by_name: None | str | Unset = UNSET,
    by_role: None | str | Unset = UNSET,
    authorization: str,
) -> list[GroupRoleInfoSchema] | None:
    """GetAll

    Args:
        by_name (None | str | Unset):
        by_role (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        list[GroupRoleInfoSchema]
    """

    return sync_detailed(
        client=client,
        by_name=by_name,
        by_role=by_role,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    by_name: None | str | Unset = UNSET,
    by_role: None | str | Unset = UNSET,
    authorization: str,
) -> Response[list[GroupRoleInfoSchema]]:
    """GetAll

    Args:
        by_name (None | str | Unset):
        by_role (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[list[GroupRoleInfoSchema]]
    """

    kwargs = _get_kwargs(
        by_name=by_name,
        by_role=by_role,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    by_name: None | str | Unset = UNSET,
    by_role: None | str | Unset = UNSET,
    authorization: str,
) -> list[GroupRoleInfoSchema] | None:
    """GetAll

    Args:
        by_name (None | str | Unset):
        by_role (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        list[GroupRoleInfoSchema]
    """

    return (
        await asyncio_detailed(
            client=client,
            by_name=by_name,
            by_role=by_role,
            authorization=authorization,
        )
    ).parsed
