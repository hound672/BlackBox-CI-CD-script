from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.pagination_schema_vuln_perimeter_schema import PaginationSchemaVulnPerimeterSchema
from ...models.severity import Severity
from ...types import UNSET, Response, Unset


def _get_kwargs(
    scan_uuid: UUID,
    *,
    severity: list[Severity] | None | Unset = UNSET,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    filter_: None | str | Unset = UNSET,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    params: dict[str, Any] = {}

    json_severity: list[str] | None | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    elif isinstance(severity, list):
        json_severity = []
        for severity_type_0_item_data in severity:
            severity_type_0_item = severity_type_0_item_data.value
            json_severity.append(severity_type_0_item)

    else:
        json_severity = severity
    params['severity'] = json_severity

    json_page: int | None | Unset
    if isinstance(page, Unset):
        json_page = UNSET
    else:
        json_page = page
    params['page'] = json_page

    json_limit: int | None | Unset
    if isinstance(limit, Unset):
        json_limit = UNSET
    else:
        json_limit = limit
    params['limit'] = json_limit

    json_filter_: None | str | Unset
    if isinstance(filter_, Unset):
        json_filter_ = UNSET
    else:
        json_filter_ = filter_
    params['filter'] = json_filter_

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/scans/{scan_uuid}/perimeter'.format(scan_uuid=quote(str(scan_uuid), safe='')),
        'params': params,
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema | None:
    if response.status_code == 200:
        response_200 = PaginationSchemaVulnPerimeterSchema.from_dict(response.json())

        return response_200

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: list[Severity] | None | Unset = UNSET,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    filter_: None | str | Unset = UNSET,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema]:
    """GetPerimeter

    Args:
        scan_uuid (UUID):
        severity (list[Severity] | None | Unset):
        page (int | None | Unset):
        limit (int | None | Unset):
        filter_ (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        severity=severity,
        page=page,
        limit=limit,
        filter_=filter_,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: list[Severity] | None | Unset = UNSET,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    filter_: None | str | Unset = UNSET,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema | None:
    """GetPerimeter

    Args:
        scan_uuid (UUID):
        severity (list[Severity] | None | Unset):
        page (int | None | Unset):
        limit (int | None | Unset):
        filter_ (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema
    """

    return sync_detailed(
        scan_uuid=scan_uuid,
        client=client,
        severity=severity,
        page=page,
        limit=limit,
        filter_=filter_,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: list[Severity] | None | Unset = UNSET,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    filter_: None | str | Unset = UNSET,
    authorization: str,
) -> Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema]:
    """GetPerimeter

    Args:
        scan_uuid (UUID):
        severity (list[Severity] | None | Unset):
        page (int | None | Unset):
        limit (int | None | Unset):
        filter_ (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        severity=severity,
        page=page,
        limit=limit,
        filter_=filter_,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    severity: list[Severity] | None | Unset = UNSET,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    filter_: None | str | Unset = UNSET,
    authorization: str,
) -> ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema | None:
    """GetPerimeter

    Args:
        scan_uuid (UUID):
        severity (list[Severity] | None | Unset):
        page (int | None | Unset):
        limit (int | None | Unset):
        filter_ (None | str | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnPerimeterSchema
    """

    return (
        await asyncio_detailed(
            scan_uuid=scan_uuid,
            client=client,
            severity=severity,
            page=page,
            limit=limit,
            filter_=filter_,
            authorization=authorization,
        )
    ).parsed
