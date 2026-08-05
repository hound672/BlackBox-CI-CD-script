from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.api_profile_short_info_schema import APIProfileShortInfoSchema
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.new_api_profile_schema import NewAPIProfileSchema
from ...types import Response


def _get_kwargs(
    *,
    body: NewAPIProfileSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/api-profiles',
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    if response.status_code == 201:
        response_201 = APIProfileShortInfoSchema.from_dict(response.json())

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
) -> Response[APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: NewAPIProfileSchema,
    authorization: str,
) -> Response[APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Create

    Args:
        authorization (str):
        body (NewAPIProfileSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
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
    body: NewAPIProfileSchema,
    authorization: str,
) -> APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Create

    Args:
        authorization (str):
        body (NewAPIProfileSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return sync_detailed(
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: NewAPIProfileSchema,
    authorization: str,
) -> Response[APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Create

    Args:
        authorization (str):
        body (NewAPIProfileSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
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
    body: NewAPIProfileSchema,
    authorization: str,
) -> APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Create

    Args:
        authorization (str):
        body (NewAPIProfileSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        APIProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
