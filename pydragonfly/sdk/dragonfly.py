import dataclasses
import logging
import time
from typing import List, Union, Set, Tuple

from django_rest_client import APIClient
from django_rest_client.types import THeaders

from .const import FAILED, REVOKED, ANALYZED
from ..version import VERSION
from .resources import (
    Action,
    Analysis,
    Invitation,
    Organization,
    Profile,
    Report,
    Rule,
    Sample,
    Session,
    UserAccessInfo,
    UserPreferences,
)


@dataclasses.dataclass
class RuleResult:
    name: str
    weight: int


@dataclasses.dataclass
class DragonflyResult:
    status: str
    evaluation: str
    score: int
    malware_family: Union[str, None]
    malware_behaviours: List[str]
    errors: List[str]
    matched_rules: List[RuleResult]
    gui_url: str


class Dragonfly(APIClient):
    # overwrite
    _server_url: str = "https://dragonfly.certego.net"

    @property
    def _headers(self) -> THeaders:
        return {
            **super()._headers,
            "User-Agent": f"PyDragonfly/{VERSION}",
        }

    def __init__(self, api_key: str, logger: logging.Logger = None):
        super().__init__(api_key, None, logger)

    # resources
    Action = Action
    Analysis = Analysis
    Invitation = Invitation
    Organization = Organization
    Profile = Profile
    Report = Report
    Rule = Rule
    Sample = Sample
    Session = Session
    UserAccessInfo = UserAccessInfo
    UserPreferences = UserPreferences

    # utilities
    @dataclasses.dataclass
    class DragonflyResultFailure(DragonflyResult):
        status: str = FAILED
        evaluation: str = FAILED
        score: int = 0
        malware_family: Union[str, None] = None
        malware_behaviours: List[str] = dataclasses.field(default_factory=list)
        errors: List[str] = dataclasses.field(default_factory=list)
        matched_rules: List[RuleResult] = dataclasses.field(default_factory=list)

    def analyze_file(
        self,
        sample_path: str,
        retrieve_result: bool = True,
        profiles: List[int] = None,
        private: bool = False,
        root: bool = False,
        os: str = None,
        arguments: List[str] = None,
        dll_entrypoints: List[str] = None,
    ) -> Union[DragonflyResult, Tuple[str, str]]:

        if profiles is None:
            profiles = [1, 2]

        with open(sample_path, "rb") as f:
            content = f.read()

        data = self.Analysis.CreateAnalysisRequestBody(
            profiles=profiles,  # this is a bit tricky. We have 2 defaults profile, one for qiling, one for speakeasy.
            private=private,  # right now we do not support private analysis anyway
            allow_actions=False,  # emulation hooks on rule matching. Not released yet
            root=root,  # your wish here, imho executing thing as users is more common
            os=os,
            # we can detected the OS on our backend. It is required if you want to analyze shellcodes unfortunately
            arguments=arguments,  # the safer approach is that the sample did not require specific arguments
            dll_entrypoints=dll_entrypoints,
            # if not entrypoints are selected, and the sample is a dll, we will emulate a maximum of 100 entrypoints
        )
        import os

        try:
            resp = self.Analysis.create(
                data=data, sample_name=os.path.basename(f.name), sample_buffer=content
            ).data
        except Exception as e:
            self._logger.exception(e)
            # if something goes wrong, we return a failure result
            if retrieve_result:
                return self.DragonflyResultFailure(gui_url=self._server_url)
        else:
            if retrieve_result:
                return self.retrieve_analysis(resp["id"])
            else:
                # if the class is not returned, at least we return the analysis id and the url
                return resp["id"], resp["gui_url"]

    def retrieve_analysis(
        self,
        analysis_id: int,
        wait_for_completion: bool = True,
        waiting_time: int = 10,
        max_wait_cycle: int = 30,
    ) -> DragonflyResult:
        try:
            content = self.Analysis.retrieve(analysis_id).data
        except Exception as e:
            self._logger.exception(e)
            return self.DragonflyResultFailure(
                gui_url=self.Analysis.instance_url(analysis_id)
            )

        status = content["status"]
        # a lazy wait for the analysis to complete

        if wait_for_completion:
            waiting_cycle: int = 0
            while (
                status not in [ANALYZED, FAILED, REVOKED]
                and waiting_cycle < max_wait_cycle
            ):
                self._logger.debug(f"Waiting {waiting_time} because {status=}")
                time.sleep(waiting_time)
                try:
                    content = self.Analysis.retrieve(object_id=analysis_id).data
                except Exception as e:
                    self._logger.exception(e)
                    return self.DragonflyResultFailure(
                        gui_url=self.Analysis.instance_url(analysis_id)
                    )
                status = content["status"]
                waiting_cycle += 1
        # there is more stuff, but I do not think that you will be interested in
        evaluation: str = content["evaluation"]
        score: int = (
            int(min(100, content["weight"]) / 10) if content["weight"] != 0 else 0
        )
        malware_family: Union[str, None] = (
            content["malware_families"][0] if content["malware_families"] else None
        )
        malware_behaviours: List[str] = content["malware_behaviours"]
        reports: List[int] = [report["id"] for report in content["reports"]]
        errors: Set[str] = set(
            [report["error"] for report in content["reports"] if report["error"]]
        )
        matched_rules: Set[RuleResult] = set()
        for report_id in reports:
            try:
                # we check the rules that matched each report
                rules = self.Report.matched_rules(object_id=report_id).data
            except Exception as e:
                self._logger.exception(e)
                return self.DragonflyResultFailure(
                    gui_url=self.Analysis.instance_url(analysis_id)
                )
            # and retrieve information about that
            for rule in rules:
                name = rule["rule"]  # name of the rule that matched
                weight = (
                    int(min(100, rule["weight"]) / 10) if rule["weight"] != 0 else 0
                )
                matched_rules.add(RuleResult(name, weight))
        # we can create our structure
        return DragonflyResult(
            status=status,
            evaluation=evaluation,
            score=score,
            malware_family=malware_family,
            malware_behaviours=malware_behaviours,
            matched_rules=list(matched_rules),
            errors=list(errors),
            gui_url=self.Analysis.instance_url(analysis_id),
        )
