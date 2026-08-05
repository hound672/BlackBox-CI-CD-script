from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define, field as _attrs_field

from ..models.crawling_type import CrawlingType
from ..models.scan_scope import ScanScope
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.header_schema import HeaderSchema
    from ..models.profile_params_schema_raw_type_0 import ProfileParamsSchemaRawType0
    from ..models.proxy_schema import ProxySchema
    from ..models.validation_schema import ValidationSchema


T = TypeVar('T', bound='ProfileParamsSchema')


@_attrs_define
class ProfileParamsSchema:
    """
    Attributes:
        blacklist (list[ValidationSchema] | None | Unset):
        crawling_type (CrawlingType | None | Unset):
        custom_headers (list[HeaderSchema] | None | Unset):
        delay_between_requests (float | None | Unset):
        modules (list[str] | None | Unset):
        proxy (None | ProxySchema | Unset):
        raw (None | ProfileParamsSchemaRawType0 | Unset):
        scan_scope (None | ScanScope | Unset):
        whitelist (list[ValidationSchema] | None | Unset):
        workers (int | None | Unset):
    """

    blacklist: list[ValidationSchema] | None | Unset = UNSET
    crawling_type: CrawlingType | None | Unset = UNSET
    custom_headers: list[HeaderSchema] | None | Unset = UNSET
    delay_between_requests: float | None | Unset = UNSET
    modules: list[str] | None | Unset = UNSET
    proxy: None | ProxySchema | Unset = UNSET
    raw: None | ProfileParamsSchemaRawType0 | Unset = UNSET
    scan_scope: None | ScanScope | Unset = UNSET
    whitelist: list[ValidationSchema] | None | Unset = UNSET
    workers: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.profile_params_schema_raw_type_0 import ProfileParamsSchemaRawType0
        from ..models.proxy_schema import ProxySchema

        blacklist: list[dict[str, Any]] | None | Unset
        if isinstance(self.blacklist, Unset):
            blacklist = UNSET
        elif isinstance(self.blacklist, list):
            blacklist = []
            for blacklist_type_0_item_data in self.blacklist:
                blacklist_type_0_item = blacklist_type_0_item_data.to_dict()
                blacklist.append(blacklist_type_0_item)

        else:
            blacklist = self.blacklist

        crawling_type: None | str | Unset
        if isinstance(self.crawling_type, Unset):
            crawling_type = UNSET
        elif isinstance(self.crawling_type, CrawlingType):
            crawling_type = self.crawling_type.value
        else:
            crawling_type = self.crawling_type

        custom_headers: list[dict[str, Any]] | None | Unset
        if isinstance(self.custom_headers, Unset):
            custom_headers = UNSET
        elif isinstance(self.custom_headers, list):
            custom_headers = []
            for custom_headers_type_0_item_data in self.custom_headers:
                custom_headers_type_0_item = custom_headers_type_0_item_data.to_dict()
                custom_headers.append(custom_headers_type_0_item)

        else:
            custom_headers = self.custom_headers

        delay_between_requests: float | None | Unset
        if isinstance(self.delay_between_requests, Unset):
            delay_between_requests = UNSET
        else:
            delay_between_requests = self.delay_between_requests

        modules: list[str] | None | Unset
        if isinstance(self.modules, Unset):
            modules = UNSET
        elif isinstance(self.modules, list):
            modules = self.modules

        else:
            modules = self.modules

        proxy: dict[str, Any] | None | Unset
        if isinstance(self.proxy, Unset):
            proxy = UNSET
        elif isinstance(self.proxy, ProxySchema):
            proxy = self.proxy.to_dict()
        else:
            proxy = self.proxy

        raw: dict[str, Any] | None | Unset
        if isinstance(self.raw, Unset):
            raw = UNSET
        elif isinstance(self.raw, ProfileParamsSchemaRawType0):
            raw = self.raw.to_dict()
        else:
            raw = self.raw

        scan_scope: None | str | Unset
        if isinstance(self.scan_scope, Unset):
            scan_scope = UNSET
        elif isinstance(self.scan_scope, ScanScope):
            scan_scope = self.scan_scope.value
        else:
            scan_scope = self.scan_scope

        whitelist: list[dict[str, Any]] | None | Unset
        if isinstance(self.whitelist, Unset):
            whitelist = UNSET
        elif isinstance(self.whitelist, list):
            whitelist = []
            for whitelist_type_0_item_data in self.whitelist:
                whitelist_type_0_item = whitelist_type_0_item_data.to_dict()
                whitelist.append(whitelist_type_0_item)

        else:
            whitelist = self.whitelist

        workers: int | None | Unset
        if isinstance(self.workers, Unset):
            workers = UNSET
        else:
            workers = self.workers

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if blacklist is not UNSET:
            field_dict['blacklist'] = blacklist
        if crawling_type is not UNSET:
            field_dict['crawlingType'] = crawling_type
        if custom_headers is not UNSET:
            field_dict['customHeaders'] = custom_headers
        if delay_between_requests is not UNSET:
            field_dict['delayBetweenRequests'] = delay_between_requests
        if modules is not UNSET:
            field_dict['modules'] = modules
        if proxy is not UNSET:
            field_dict['proxy'] = proxy
        if raw is not UNSET:
            field_dict['raw'] = raw
        if scan_scope is not UNSET:
            field_dict['scanScope'] = scan_scope
        if whitelist is not UNSET:
            field_dict['whitelist'] = whitelist
        if workers is not UNSET:
            field_dict['workers'] = workers

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.header_schema import HeaderSchema
        from ..models.profile_params_schema_raw_type_0 import ProfileParamsSchemaRawType0
        from ..models.proxy_schema import ProxySchema
        from ..models.validation_schema import ValidationSchema

        d = dict(src_dict)

        def _parse_blacklist(data: object) -> list[ValidationSchema] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                blacklist_type_0 = []
                _blacklist_type_0 = data
                for blacklist_type_0_item_data in _blacklist_type_0:
                    blacklist_type_0_item = ValidationSchema.from_dict(blacklist_type_0_item_data)

                    blacklist_type_0.append(blacklist_type_0_item)

                return blacklist_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ValidationSchema] | None | Unset, data)

        blacklist = _parse_blacklist(d.pop('blacklist', UNSET))

        def _parse_crawling_type(data: object) -> CrawlingType | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                crawling_type_type_0 = CrawlingType(data)

                return crawling_type_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CrawlingType | None | Unset, data)

        crawling_type = _parse_crawling_type(d.pop('crawlingType', UNSET))

        def _parse_custom_headers(data: object) -> list[HeaderSchema] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                custom_headers_type_0 = []
                _custom_headers_type_0 = data
                for custom_headers_type_0_item_data in _custom_headers_type_0:
                    custom_headers_type_0_item = HeaderSchema.from_dict(custom_headers_type_0_item_data)

                    custom_headers_type_0.append(custom_headers_type_0_item)

                return custom_headers_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[HeaderSchema] | None | Unset, data)

        custom_headers = _parse_custom_headers(d.pop('customHeaders', UNSET))

        def _parse_delay_between_requests(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        delay_between_requests = _parse_delay_between_requests(d.pop('delayBetweenRequests', UNSET))

        def _parse_modules(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                modules_type_0 = cast(list[str], data)

                return modules_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        modules = _parse_modules(d.pop('modules', UNSET))

        def _parse_proxy(data: object) -> None | ProxySchema | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                proxy_type_0 = ProxySchema.from_dict(data)

                return proxy_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ProxySchema | Unset, data)

        proxy = _parse_proxy(d.pop('proxy', UNSET))

        def _parse_raw(data: object) -> None | ProfileParamsSchemaRawType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError
                raw_type_0 = ProfileParamsSchemaRawType0.from_dict(data)

                return raw_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ProfileParamsSchemaRawType0 | Unset, data)

        raw = _parse_raw(d.pop('raw', UNSET))

        def _parse_scan_scope(data: object) -> None | ScanScope | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError
                scan_scope_type_0 = ScanScope(data)

                return scan_scope_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ScanScope | Unset, data)

        scan_scope = _parse_scan_scope(d.pop('scanScope', UNSET))

        def _parse_whitelist(data: object) -> list[ValidationSchema] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError
                whitelist_type_0 = []
                _whitelist_type_0 = data
                for whitelist_type_0_item_data in _whitelist_type_0:
                    whitelist_type_0_item = ValidationSchema.from_dict(whitelist_type_0_item_data)

                    whitelist_type_0.append(whitelist_type_0_item)

                return whitelist_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ValidationSchema] | None | Unset, data)

        whitelist = _parse_whitelist(d.pop('whitelist', UNSET))

        def _parse_workers(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        workers = _parse_workers(d.pop('workers', UNSET))

        profile_params_schema = cls(
            blacklist=blacklist,
            crawling_type=crawling_type,
            custom_headers=custom_headers,
            delay_between_requests=delay_between_requests,
            modules=modules,
            proxy=proxy,
            raw=raw,
            scan_scope=scan_scope,
            whitelist=whitelist,
            workers=workers,
        )

        profile_params_schema.additional_properties = d
        return profile_params_schema

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
