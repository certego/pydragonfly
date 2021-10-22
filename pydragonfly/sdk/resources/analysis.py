import json
import dataclasses
from typing import Optional, List
from typing_extensions import Literal

from django_rest_client import (
    APIResponse,
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    PaginationAPIResourceMixin,
)
from django_rest_client.types import Toid, TParams


@dataclasses.dataclass
class CreateAnalysisRequestBody:
    profiles: List[int]
    private: bool = False
    allow_actions: bool = False
    root: bool = False
    os: Optional[Literal["WINDOWS", "LINUX"]] = None
    arguments: Optional[List[str]] = None


class Analysis(
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    PaginationAPIResourceMixin,
):
    """
    :class:`pydragonfly.Dragonfly.Analysis`
    """

    OBJECT_NAME = "api.analysis"
    EXPANDABLE_FIELDS = {
        "retrieve": ["sample", "reports"],
        "list": [],
    }
    ORDERING_FIELDS = [
        "created_at",
        "sample__filename",
        "weight",
    ]
    CreateAnalysisRequestBody = CreateAnalysisRequestBody

    @classmethod
    def create(
        cls,
        data: CreateAnalysisRequestBody,
        sample_name: str,
        sample_buffer: bytes,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = "api/create_analysis"
        post_data = {
            "data": json.dumps(
                {k: v for k, v in dataclasses.asdict(data).items() if v is not None}
            )
        }
        post_files = {"sample": (sample_name, sample_buffer)}
        response = cls._request(
            "POST",
            url=url,
            data=post_data,
            files=post_files,
            params=params,
        )
        return response

    @classmethod
    def aggregate_evaluations(
        cls,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = cls.class_url() + "/aggregate/evaluations"
        return cls._request("GET", url=url, params=params)

    @classmethod
    def aggregate_status(
        cls,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = cls.class_url() + "/aggregate/status"
        return cls._request("GET", url=url, params=params)

    @classmethod
    def aggregate_malware_families(
        cls,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = cls.class_url() + "/aggregate/malware_families"
        return cls._request("GET", url=url, params=params)

    @classmethod
    def aggregate_malware_type(
        cls,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = cls.class_url() + "/aggregate/malware_type"
        return cls._request("GET", url=url, params=params)

    @classmethod
    def revoke(
        cls,
        object_id: Toid,
        params: Optional[TParams] = None,
    ) -> APIResponse:
        url = cls.instance_url(object_id) + "/revoke"
        return cls._request("POST", url=url, params=params)
