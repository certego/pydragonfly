from typing import Optional

from drf_client import (
    APIResponse,
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    PaginationAPIResourceMixin,
)
from drf_client.types import Toid, TParams


class Report(
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    PaginationAPIResourceMixin,
):
    OBJECT_NAME = "api.report"
    EXPANDABLE_FIELDS = {
        "retrieve": ["profile", "analysis"],
        "list": ["profile", "analysis"],
    }
    ORDERING_FIELDS = [
        "time__start_analysis",
        "analysis__sample__filename",
        "weight",
    ]

    @classmethod
    def timeline(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id) + "/timeline"
        return cls._request("GET", url=url, params=params)

    @classmethod
    def matched_rules(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id) + "/matched_rules"
        return cls._request("GET", url=url, params=params)

    @classmethod
    def revoke(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id) + "/revoke"
        return cls._request("POST", url=url, params=params)
