import logging
import time
from typing import List, Union

from django_rest_client import APIClient
from django_rest_client.types import THeaders, Toid

from .resources.analysis import AnalysisResult
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
            sample_path: str,
            profiles: List[int] = None,
            private: bool = False,
            root: bool = False,
            os: str = None,
            arguments: List[str] = None,
            dll_entrypoints: List[str] = None,
    ) -> Union[AnalysisResult]:

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

        else:
            return self.analysis_result(resp["id"])


    def analysis_result(self, analysis_id: Toid, waiting_time: int = 10,
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