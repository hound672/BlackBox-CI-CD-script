from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_invalid_modules import ErrorSchemaInvalidModules
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.profile_short_info_schema import ProfileShortInfoSchema
from ...models.profile_update_schema import ProfileUpdateSchema
from ...types import Response


def _get_kwargs(
    profile_uuid: UUID,
    *,
    body: ProfileUpdateSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'patch',
        'url': '/api/v1/profiles/{profile_uuid}'.format(profile_uuid=quote(str(profile_uuid), safe='')),
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ErrorSchemaInvalidModules
    | ErrorSchemaNoneType
    | ErrorSchemaRoleAttributeDescriptionSchema
    | ProfileShortInfoSchema
    | None
):
    if response.status_code == 200:
        response_200 = ProfileShortInfoSchema.from_dict(response.json())

        return response_200

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = ErrorSchemaInvalidModules.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: ProfileUpdateSchema,
    authorization: str,
) -> Response[
    ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema
]:
    """Update

    Args:
        profile_uuid (UUID):
        authorization (str):
        body (ProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema]
    """

    kwargs = _get_kwargs(
        profile_uuid=profile_uuid,
        body=body,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: ProfileUpdateSchema,
    authorization: str,
) -> (
    ErrorSchemaInvalidModules
    | ErrorSchemaNoneType
    | ErrorSchemaRoleAttributeDescriptionSchema
    | ProfileShortInfoSchema
    | None
):
    """Update

    Args:
        profile_uuid (UUID):
        authorization (str):
        body (ProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema
    """

    return sync_detailed(
        profile_uuid=profile_uuid,
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: ProfileUpdateSchema,
    authorization: str,
) -> Response[
    ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema
]:
    """Update

    Args:
        profile_uuid (UUID):
        authorization (str):
        body (ProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema]
    """

    kwargs = _get_kwargs(
        profile_uuid=profile_uuid,
        body=body,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: ProfileUpdateSchema,
    authorization: str,
) -> (
    ErrorSchemaInvalidModules
    | ErrorSchemaNoneType
    | ErrorSchemaRoleAttributeDescriptionSchema
    | ProfileShortInfoSchema
    | None
):
    """Update

    Args:
        profile_uuid (UUID):
        authorization (str):
        body (ProfileUpdateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaInvalidModules | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | ProfileShortInfoSchema
    """

    return (
        await asyncio_detailed(
            profile_uuid=profile_uuid,
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
