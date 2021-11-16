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
    dll_entrypoints: Optional[List[str]] = None


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
        # first: POST sample uploading it
        url1 = "api/sample"
        req_data1 = {"sample": (sample_name, sample_buffer)}
        response1 = cls._request(
            "POST",
            url=url1,
            files=req_data1,
        )
        # second: POST analysis using the new sample ID
        url2 = "api/create_analysis"
        req_data2 = {
            **{k: v for k, v in dataclasses.asdict(data).items() if v is not None},
            "sample_id": response1.data["id"],
        }
        response2 = cls._request(
            "POST",
            url=url2,
            data=req_data2,
            params=params,
        )
        return response2

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
