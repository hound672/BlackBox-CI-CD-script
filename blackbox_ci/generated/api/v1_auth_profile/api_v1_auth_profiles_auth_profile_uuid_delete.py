from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_auth_profiles_conflicts import ErrorSchemaAuthProfilesConflicts
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...types import Response


def _get_kwargs(
    auth_profile_uuid: UUID,
    *,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'delete',
        'url': '/api/v1/auth-profiles/{auth_profile_uuid}'.format(
            auth_profile_uuid=quote(str(auth_profile_uuid), safe='')
        ),
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if response.status_code == 409:
        response_409 = ErrorSchemaAuthProfilesConflicts.from_dict(response.json())

        return response_409

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
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
    authorization: str,
) -> Response[Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Delete

    Args:
        auth_profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        auth_profile_uuid=auth_profile_uuid,
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
    authorization: str,
) -> Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Delete

    Args:
        auth_profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return sync_detailed(
        auth_profile_uuid=auth_profile_uuid,
        client=client,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    auth_profile_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    authorization: str,
) -> Response[Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]:
    """Delete

    Args:
        auth_profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema]
    """

    kwargs = _get_kwargs(
        auth_profile_uuid=auth_profile_uuid,
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
    authorization: str,
) -> Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | None:
    """Delete

    Args:
        auth_profile_uuid (UUID):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaAuthProfilesConflicts | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema
    """

    return (
        await asyncio_detailed(
            auth_profile_uuid=auth_profile_uuid,
            client=client,
            authorization=authorization,
        )
    ).parsed
