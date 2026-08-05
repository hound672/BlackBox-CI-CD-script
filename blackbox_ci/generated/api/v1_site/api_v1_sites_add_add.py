from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.site_create_schema import SiteCreateSchema
from ...models.site_schema import SiteSchema
from ...types import Response


def _get_kwargs(
    *,
    body: SiteCreateSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/sites/add',
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema | None:
    if response.status_code == 201:
        response_201 = SiteSchema.from_dict(response.json())

        return response_201

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 422:
        response_422 = ErrorSchemaNoneType.from_dict(response.json())

        return response_422

    if response.status_code == 503:
        response_503 = ErrorSchemaNoneType.from_dict(response.json())

        return response_503

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: SiteCreateSchema,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema]:
    """Add

    Args:
        authorization (str):
        body (SiteCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema]
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
    body: SiteCreateSchema,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema | None:
    """Add

    Args:
        authorization (str):
        body (SiteCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema
    """

    return sync_detailed(
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: SiteCreateSchema,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema]:
    """Add

    Args:
        authorization (str):
        body (SiteCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema]
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
    body: SiteCreateSchema,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema | None:
    """Add

    Args:
        authorization (str):
        body (SiteCreateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSchema
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
