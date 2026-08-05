from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.auth_profile_short_info_schema import AuthProfileShortInfoSchema
from ...models.auth_profile_update_schema import AuthProfileUpdateSchema
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...types import Response


def _get_kwargs(
    auth_profile_uuid: UUID,
    *,
    body: AuthProfileUpdateSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'patch',
        'url': '/api/v1/auth-profiles/{auth_profile_uuid}'.format(
            auth_profile_uuid=quote(str(auth_profile_uuid), safe='')
        ),
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    if response.status_code == 200:
        response_200 = AuthProfileShortInfoSchema.from_dict(response.json())

        return response_200

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
) -> Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    auth_profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileUpdateSchema,
    authorization: str,
) -> Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Patch

    Args:
        auth_profile_uuid (UUID):
        authorization (str):
        body (AuthProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        auth_profile_uuid=auth_profile_uuid,
        body=body,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    auth_profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileUpdateSchema,
    authorization: str,
) -> AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Patch

    Args:
        auth_profile_uuid (UUID):
        authorization (str):
        body (AuthProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return sync_detailed(
        auth_profile_uuid=auth_profile_uuid,
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    auth_profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileUpdateSchema,
    authorization: str,
) -> Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Patch

    Args:
        auth_profile_uuid (UUID):
        authorization (str):
        body (AuthProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        auth_profile_uuid=auth_profile_uuid,
        body=body,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    auth_profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: AuthProfileUpdateSchema,
    authorization: str,
) -> AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Patch

    Args:
        auth_profile_uuid (UUID):
        authorization (str):
        body (AuthProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AuthProfileShortInfoSchema | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return (
        await asyncio_detailed(
            auth_profile_uuid=auth_profile_uuid,
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
