from typing import Optional

from drf_client import (
    APIResponse,
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    UpdateableAPIResourceMixin,
    PaginationAPIResourceMixin,
)
from drf_client.types import TParams


class Rule(
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    UpdateableAPIResourceMixin,
    PaginationAPIResourceMixin,
):
    OBJECT_NAME = "api.rule"
    EXPANDABLE_FIELDS = {
        "retrieve": ["user", "actions", "clause", "permissions"],
        "list": ["user", "permissions"],
    }
    ORDERING_FIELDS = [
        "created_at",
        "rule",
        "weight",
        "malware_family",
        "malware_behaviour",
    ]

    @classmethod
    def aggregate_malware_behaviour(
        cls,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.class_url() + "/aggregate/malware_behaviour"
        return cls._request("GET", url=url, params=params)
