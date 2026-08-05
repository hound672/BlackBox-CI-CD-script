from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_schema_none_type import ErrorSchemaNoneType
from ...models.error_schema_role_attribute_description_schema import ErrorSchemaRoleAttributeDescriptionSchema
from ...models.pagination_schema_vuln_in_group_schema import PaginationSchemaVulnInGroupSchema
from ...models.severity import Severity
from ...models.vulnerability_issue import VulnerabilityIssue
from ...types import UNSET, Response, Unset


def _get_kwargs(
    scan_uuid: UUID,
    issue_type: VulnerabilityIssue,
    group_name: str,
    severity: Severity,
    *,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    authorization: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    headers['authorization'] = authorization

    params: dict[str, Any] = {}

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

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/scans/{scan_uuid}/vulnerabilities/{issue_type}/{group_name}/{severity}'.format(
            scan_uuid=quote(str(scan_uuid), safe=''),
            issue_type=quote(str(issue_type), safe=''),
            group_name=quote(str(group_name), safe=''),
            severity=quote(str(severity), safe=''),
        ),
        'params': params,
    }

    _kwargs['headers'] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema | None:
    if response.status_code == 200:
        response_200 = PaginationSchemaVulnInGroupSchema.from_dict(response.json())

        return response_200

    if response.status_code == 403:
        response_403 = ErrorSchemaRoleAttributeDescriptionSchema.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorSchemaNoneType.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = cast(Any, None)
        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    scan_uuid: UUID,
    issue_type: VulnerabilityIssue,
    group_name: str,
    severity: Severity,
    *,
    client: AuthenticatedClient | Client,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    authorization: str,
) -> Response[
    Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema
]:
    """GetInGroup

    Args:
        scan_uuid (UUID):
        issue_type (VulnerabilityIssue):
        group_name (str):
        severity (Severity):
        page (int | None | Unset):
        limit (int | None | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        issue_type=issue_type,
        group_name=group_name,
        severity=severity,
        page=page,
        limit=limit,
        authorization=authorization,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    scan_uuid: UUID,
    issue_type: VulnerabilityIssue,
    group_name: str,
    severity: Severity,
    *,
    client: AuthenticatedClient | Client,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    authorization: str,
) -> Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema | None:
    """GetInGroup

    Args:
        scan_uuid (UUID):
        issue_type (VulnerabilityIssue):
        group_name (str):
        severity (Severity):
        page (int | None | Unset):
        limit (int | None | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema
    """

    return sync_detailed(
        scan_uuid=scan_uuid,
        issue_type=issue_type,
        group_name=group_name,
        severity=severity,
        client=client,
        page=page,
        limit=limit,
        authorization=authorization,
    ).parsed


async def asyncio_detailed(
    scan_uuid: UUID,
    issue_type: VulnerabilityIssue,
    group_name: str,
    severity: Severity,
    *,
    client: AuthenticatedClient | Client,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    authorization: str,
) -> Response[
    Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema
]:
    """GetInGroup

    Args:
        scan_uuid (UUID):
        issue_type (VulnerabilityIssue):
        group_name (str):
        severity (Severity):
        page (int | None | Unset):
        limit (int | None | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        issue_type=issue_type,
        group_name=group_name,
        severity=severity,
        page=page,
        limit=limit,
        authorization=authorization,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio(
    scan_uuid: UUID,
    issue_type: VulnerabilityIssue,
    group_name: str,
    severity: Severity,
    *,
    client: AuthenticatedClient | Client,
    page: int | None | Unset = UNSET,
    limit: int | None | Unset = UNSET,
    authorization: str,
) -> Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema | None:
    """GetInGroup

    Args:
        scan_uuid (UUID):
        issue_type (VulnerabilityIssue):
        group_name (str):
        severity (Severity):
        page (int | None | Unset):
        limit (int | None | Unset):
        authorization (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | ErrorSchemaNoneType | ErrorSchemaRoleAttributeDescriptionSchema | PaginationSchemaVulnInGroupSchema
    """

    return (
        await asyncio_detailed(
            scan_uuid=scan_uuid,
            issue_type=issue_type,
            group_name=group_name,
            severity=severity,
            client=client,
            page=page,
            limit=limit,
            authorization=authorization,
        )
    ).parsed
