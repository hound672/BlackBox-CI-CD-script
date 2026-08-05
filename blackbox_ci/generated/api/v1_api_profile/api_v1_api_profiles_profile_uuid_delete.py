from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_api_profiles_conflicts import ErrorSchemaAPIProfilesConflicts
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...types import Response


def _get_kwargs(
    profile_uuid: UUID,
    *,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'delete',
        'url': '/api/v1/api-profiles/{profile_uuid}'.format(profile_uuid=quote(str(profile_uuid), safe='')),
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema | None:
    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 409:
        response_409 = ErrorSchemaAPIProfilesConflicts.from_dict(response.json())

        return response_409

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema]:
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
    authorization: str,
) -> Response[Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Delete

    Args:
        profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        profile_uuid=profile_uuid,
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
    authorization: str,
) -> Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Delete

    Args:
        profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return sync_detailed(
        profile_uuid=profile_uuid,
        client=client,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Delete

    Args:
        profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        profile_uuid=profile_uuid,
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
    authorization: str,
) -> Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Delete

    Args:
        profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaAPIProfilesConflicts | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return (
        await asyncio_detailed(
            profile_uuid=profile_uuid,
            client=client,
            authorization=authorization,
        )
    ).parsed
