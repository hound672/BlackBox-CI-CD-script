from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.auth_profile_create_schema import AuthProfileCreateSchema
from ...models.auth_profile_short_info_schema import AuthProfileShortInfoSchema
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...types import Response


def _get_kwargs(
    *,
    body: AuthProfileCreateSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/auth-profiles',
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    if response.status_code == 201:
        response_201 = AuthProfileShortInfoSchema.from_dict(response.json())

        return response_201

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 422:
        response_422 = ErrorSchemaNoneType.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileCreateSchema,
    authorization: str,
) -> Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Post

    Args:
        authorization (str):
        body (AuthProfileCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        body=body,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileCreateSchema,
    authorization: str,
) -> AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Post

    Args:
        authorization (str):
        body (AuthProfileCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return sync_detailed(
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileCreateSchema,
    authorization: str,
) -> Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Post

    Args:
        authorization (str):
        body (AuthProfileCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        body=body,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileCreateSchema,
    authorization: str,
) -> AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Post

    Args:
        authorization (str):
        body (AuthProfileCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
