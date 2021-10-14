from typing import Optional

from drf_client import (
    APIResource,
    APIResponse,
    ListableAPIResourceMixin,
    DeletableAPIResourceMixin,
)
from drf_client.types import Toid, TParams


class Invitation(
    APIResource,
    ListableAPIResourceMixin,
    DeletableAPIResourceMixin,
):
    OBJECT_NAME = "api.me.invitations"
    EXPANDABLE_FIELDS = {
        "retrieve": [],
        "list": [],
    }
    ORDERING_FIELDS = []

    @classmethod
    def accept(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id) + "/accept"
        return cls._request("POST", url=url, params=params)

    @classmethod
    def decline(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id) + "/decline"
        return cls._request("POST", url=url, params=params)
