from typing import Optional
import dataclasses
from drf_client import (
    APIResource,
    APIResponse,
    CreateableAPIResourceMixin,
    SingletonAPIResourceMixin,
)
from drf_client.types import TParams


@dataclasses.dataclass
class InviteRequestBody:
    username: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class RemoveMemberRequestBody(InviteRequestBody):
    pass


class Organization(
    APIResource,
    SingletonAPIResourceMixin,
    CreateableAPIResourceMixin,
):
    """
    Note: ``delete`` and ``leave`` methods are
    intentionally not provided to avoid accidents.
    Please use the GUI for those operations.
    """

    OBJECT_NAME = "api.me.organization"
    EXPANDABLE_FIELDS = {
        "retrieve": ["members", "pending_invitations"],
        "list": ["members", "pending_invitations"],
    }
    ORDERING_FIELDS = []

    # models
    InviteRequestBody = InviteRequestBody
    RemoveMemberRequestBody = RemoveMemberRequestBody

    @classmethod
    def invite(
        cls,
        data: InviteRequestBody,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.class_url() + "/invite"
        return cls._request("POST", url=url, data=data.to_dict(), params=params)

    @classmethod
    def remove_member(
        cls,
        data: RemoveMemberRequestBody,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.class_url() + "/remove_member"
        return cls._request("POST", url=url, data=data.to_dict(), params=params)
