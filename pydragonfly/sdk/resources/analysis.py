import dataclasses
from typing import Optional, List, Union, Set
from typing_extensions import Literal

from django_rest_client import (
    APIResponse,
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    PaginationAPIResourceMixin,
)
from django_rest_client.types import Toid, TParams
import logging

from pydragonfly.sdk.const import FAILED, REVOKED, ANALYZED, CLEAN

logger = logging.getLogger(__name__)


class AnalysisResult:
    @dataclasses.dataclass
    class RuleResult:
        name: str
        weight: int

        def __hash__(self):
            return hash((self.name, self.weight))

        def __eq__(self, other):
            return self.name == other.name and self.weight == other.weight

    status: str
    evaluation: str = CLEAN
    score: int = 0
    malware_family: str = None
    malware_behaviours: List[str] = []
    errors: List[str] = []
    matched_rules: List[RuleResult] = []
    gui_url: str

    def __init__(self, analysis_id: Toid):
        self.id = analysis_id
        self.gui_url = Analysis.instance_url(self.id)
        try:
            content = Analysis.retrieve(self.id).data
        except Exception as e:
            logger.exception(e)
            self.status = FAILED
        else:
            self.status = content["status"]
            if self.is_ready():
                self.populate(content)

    def populate(self, data: Optional[dict] = None):
        if data is None:
            try:
                content = Analysis.retrieve(self.id).data
            except Exception as e:
                logger.exception(e)
                self.status = FAILED
                return
        else:
            content = data
        self.status = content["status"]
        if self.is_ready():

            self.evaluation: str = content["evaluation"]
            self.score: int = (
                round(min(100, content["weight"]) / 10) if content["weight"] != 0 else 0
            )
            self.malware_family: Union[str, None] = (
                content["malware_families"][0] if content["malware_families"] else None
            )
            self.malware_behaviours: List[str] = content["malware_behaviours"]
            reports: List[int] = [report["id"] for report in content["reports"]]
            self.errors: List[str] = list(set(
                [report["error"] for report in content["reports"] if report["error"]]
            ))
            matched_rules: Set[AnalysisResult.RuleResult] = set()
            from pydragonfly.sdk.resources import Report

            for report_id in reports:
                try:
                    # we check the rules that matched each report
                    rules = Report.matched_rules(object_id=report_id).data
                except Exception as e:
                    logger.exception(e)
                else:
                    # and retrieve information about that
                    for rule in rules:
                        name = rule["rule"]  # name of the rule that matched
                        weight = (
                            round(min(100, rule["weight"]) / 10) if rule["weight"] != 0 else 0
                        )
                        matched_rules.add(AnalysisResult.RuleResult(name, weight))
            self.matched_rules = list(matched_rules)

    def is_ready(self) -> bool:
        return self.status in [ANALYZED, FAILED, REVOKED]


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
    CreateableAPIResourceMixin,
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
    Result = AnalysisResult

    @classmethod
    def create(
            cls,
            data: CreateAnalysisRequestBody,
            sample_name: str,
            sample_buffer: bytes,
            params: Optional[TParams] = None,
    ) -> APIResponse:
        # first: POST sample uploading it
        resp1 = cls._request(
            "POST",
            url="api/sample",
            files={"sample": (sample_name, sample_buffer)},
        )
        # second: POST analysis using the new sample ID
        # build request body
        req_data = {
            **{k: v for k, v in dataclasses.asdict(data).items() if v is not None},
            "sample_id": resp1.data["id"],
        }
        if resp1.data["malware_type"] == "DLL":
            req_data["dll_entrypoints"] = (
                data.dll_entrypoints
                if data.dll_entrypoints
                else resp1.data["entry_points"]
            )  # dll_entrypoints is required in case of DLL
        resp2 = cls._request(
            "POST",
            url=cls.class_url(),
            json=req_data,
            params=params,
        )
        return resp2

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
