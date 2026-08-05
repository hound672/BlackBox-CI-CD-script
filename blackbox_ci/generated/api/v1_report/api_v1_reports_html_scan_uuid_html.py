from http import HTTPStatus
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.report_lang_enum import ReportLangEnum
from ...models.template_name import TemplateName
from ...types import UNSET, Response


def _get_kwargs(
    scan_uuid: UUID,
    *,
    locale: ReportLangEnum,
    template: TemplateName,
) -> dict[str, Any]:
    params: dict[str, Any] = {}

    json_locale = locale.value
    params['locale'] = json_locale

    json_template = template.value
    params['template'] = json_template

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        'method': 'get',
        'url': '/api/v1/reports/html/{scan_uuid}'.format(scan_uuid=quote(str(scan_uuid), safe='')),
        'params': params,
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | None:
    if response.status_code == 200:
        return None

    if response.status_code == 403:
        return None

    if response.status_code == 404:
        return None

    if response.status_code == 503:
        return None

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any]:
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
    locale: ReportLangEnum,
    template: TemplateName,
) -> Response[Any]:
    """Html

    Args:
        scan_uuid (UUID):
        locale (ReportLangEnum):
        template (TemplateName):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        locale=locale,
        template=template,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio_detailed(
    scan_uuid: UUID,
    *,
    client: AuthenticatedClient | Client,
    locale: ReportLangEnum,
    template: TemplateName,
) -> Response[Any]:
    """Html

    Args:
        scan_uuid (UUID):
        locale (ReportLangEnum):
        template (TemplateName):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        scan_uuid=scan_uuid,
        locale=locale,
        template=template,
    )

    response = await client.get_async_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)
