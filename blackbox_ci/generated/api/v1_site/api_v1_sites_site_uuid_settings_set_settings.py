from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.site_set_settings_schema import SiteSetSettingsSchema
from ...models.site_settings_info_schema import SiteSettingsInfoSchema
from ...types import Response


def _get_kwargs(
    site_uuid: UUID,
    *,
    body: SiteSetSettingsSchema,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    _kwargs: dict[str, Any] = {
        'method': 'post',
        'url': '/api/v1/sites/{site_uuid}/settings'.format(site_uuid=quote(str(site_uuid), safe='')),
    }

    _kwargs['json'] = body.to_dict()

    headers['Content-Type'] = 'application/json'

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema | None:
    if response.status_code == 201:
        response_201 = SiteSettingsInfoSchema.from_dict(response.json())

        return response_201

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
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: SiteSetSettingsSchema,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema]:
    """SetSettings

    Args:
        site_uuid (UUID):
        authorization (str):
        body (SiteSetSettingsSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema]
    """

    kwargs = _get_kwargs(
        site_uuid=site_uuid,
        body=body,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: SiteSetSettingsSchema,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema | None:
    """SetSettings

    Args:
        site_uuid (UUID):
        authorization (str):
        body (SiteSetSettingsSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema
    """

    return sync_detailed(
        site_uuid=site_uuid,
        client=client,
        body=body,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: SiteSetSettingsSchema,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema]:
    """SetSettings

    Args:
        site_uuid (UUID):
        authorization (str):
        body (SiteSetSettingsSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema]
    """

    kwargs = _get_kwargs(
        site_uuid=site_uuid,
        body=body,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    site_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    body: SiteSetSettingsSchema,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema | None:
    """SetSettings

    Args:
        site_uuid (UUID):
        authorization (str):
        body (SiteSetSettingsSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | SiteSettingsInfoSchema
    """

    return (
        await asyncio_detailed(
            site_uuid=site_uuid,
            client=client,
            body=body,
            authorization=authorization,
        )
    ).parsed
