import dataclasses
from typing import Optional, List
from typing_extensions import Literal
from django_rest_client import (
    APIResource,
    APIResponse,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    UpdateableAPIResourceMixin,
    PaginationAPIResourceMixin,
)
from django_rest_client.types import Toid, TParams


@dataclasses.dataclass
class CreateRuleRequestBody:
    rule: str
    weight: int
    modules: dict
    variables: List[str] = dataclasses.field(default_factory=list)
    malware_family: str = ""
    malware_behaviour: Literal[
        "PUA",
        "Riskware",
        "Adware",
        "Greyware",
        "Downloader",
        "Bot",
        "Trojan",
        "Backdoor",
        "Coinminer",
        "Worm",
        "Rootkit",
        "Infostealer",
        "Banker",
        "Ransomware",
        "Spyware",
        "Miner",
        "Unpacker",
    ] = ""
    meta_description: dict = dataclasses.field(default_factory=dict)
    sensitive: bool = False


@dataclasses.dataclass
class UpdateRuleRequestBody:
    enabled: bool


class Rule(
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    UpdateableAPIResourceMixin,
    PaginationAPIResourceMixin,
):
    """
    :class:`pydragonfly.Dragonfly.Rule`
    """

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

    # models
    CreateRuleRequestBody = CreateRuleRequestBody
    UpdateRuleRequestBody = UpdateRuleRequestBody

    @classmethod
    def create(
        cls,
        data: CreateRuleRequestBody,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        post_data = dataclasses.asdict(data)
        return super().create(data=post_data, params=params)

    @classmethod
    def update(
        cls,
        object_id: Toid,
        data: UpdateRuleRequestBody,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        post_data = {
            "enabled": data.enabled,
        }
        return super().update(object_id=object_id, data=post_data, params=params)

    @classmethod
    def aggregate_malware_behaviour(
        cls,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = cls.class_url() + "/aggregate/malware_behaviour"
        return cls._request("GET", url=url, params=params)
