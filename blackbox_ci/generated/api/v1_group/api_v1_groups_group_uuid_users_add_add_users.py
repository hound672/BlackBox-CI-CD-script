from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.user_role_schema import UserRoleSchema
from ...types import Response


def _get_kwargs(
    group_uuid: UUID,
    *,
    body: list[UserRoleSchema],
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/groups/{group_uuid}/users/add'.format(group_uuid=quote(str(group_uuid), safe='')),
    }

    _kwargs['json'] = []
    for body_item_data in body:
        body_item = body_item_data.to_dict()
        _kwargs['json'].append(body_item)

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = ErrorSchemaNoneType.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
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
    body: list[UserRoleSchema],
    authorization: str,
) -> Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """AddUsers

    Args:
        group_uuid (UUID):
        authorization (str):
        body (list[UserRoleSchema]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        group_uuid=group_uuid,
        body=body,
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
    body: list[UserRoleSchema],
    authorization: str,
) -> Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """AddUsers

    Args:
        group_uuid (UUID):
        authorization (str):
        body (list[UserRoleSchema]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return sync_detailed(
        group_uuid=group_uuid,
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    group_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: list[UserRoleSchema],
    authorization: str,
) -> Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """AddUsers

    Args:
        group_uuid (UUID):
        authorization (str):
        body (list[UserRoleSchema]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        group_uuid=group_uuid,
        body=body,
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
    body: list[UserRoleSchema],
    authorization: str,
) -> Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """AddUsers

    Args:
        group_uuid (UUID):
        authorization (str):
        body (list[UserRoleSchema]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return (
        await asyncio_detailed(
            group_uuid=group_uuid,
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
