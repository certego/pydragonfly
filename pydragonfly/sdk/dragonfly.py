import io
import logging
import time
from typing import List, Union

from django_rest_client import APIClient
from django_rest_client.types import THeaders, Toid

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
from .resources.analysis import AnalysisResult


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

    def analyze_file(
        self,
        sample: io.IOBase,
        sample_name: str,
        retrieve_analysis: bool = True,
        profiles: List[int] = None,
        private: bool = False,
        root: bool = False,
        operating_system: str = None,
        arguments: List[str] = None,
        dll_entrypoints: List[str] = None,
    ) -> Union[AnalysisResult, int]:
        if profiles is None:
            profiles = [1, 2]
        content = sample.read()
        data = self.Analysis.CreateAnalysisRequestBody(
            # We have 2 defaults profile, one for qiling, one for speakeasy.
            profiles=profiles,
            # right now we do not support private analysis anyway
            private=private,
            # emulation hooks on rule matching. Not released yet
            allow_actions=False,
            # your wish here, imho executing thing as users is more common
            root=root,
            # we can detected the OS on our backend.
            # It is required if you want to analyze shellcodes unfortunately
            os=operating_system,
            # the safer approach is that the sample did not require specific arguments
            arguments=arguments,
            # if not entrypoints are selected, and the sample is a dll
            # we will emulate a maximum of 100 entrypoints
            dll_entrypoints=dll_entrypoints,
        )
        try:
            resp = self.Analysis.create(
                data=data, sample_name=sample_name, sample_buffer=content
            ).data
        except Exception as e:
            self._logger.exception(e)
            # if something goes wrong, we return a failure result

        else:
            id = resp["id"]
            if retrieve_analysis:
                return self.analysis_result(id)
            else:
                return id

    def analysis_result(
        self,
        analysis_id: Toid,
        waiting_time: int = 10,
        max_wait_cycle: int = 30,  # 30 x 10 = 5 mins
    ) -> AnalysisResult:
        result = self.Analysis.Result(analysis_id)
        if max_wait_cycle:
            waiting_cycle: int = 0
            while not result.is_ready() and waiting_cycle < max_wait_cycle:
                time.sleep(waiting_time)
                result.populate()
                waiting_cycle += 1
        return result
