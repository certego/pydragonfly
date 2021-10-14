import logging
from drf_client import APIClient

from .version import VERSION
from .resources import (
    Action,
    Analysis,
    Invitation,
    Organization,
    Profile,
    Report,
    Rule,
    Sample,
    UserAccessInfo,
)


class Dragonfly(APIClient):
    # overwrite
    _server_url: str = "http://localhost"  # FIXME
    _headers = {"User-Agent": f"PyDragonfly/{VERSION}"}

    def __init__(self, token: str, logger: logging.Logger = None):
        super().__init__(token, None, logger)

    # resources
    Action = Action
    Analysis = Analysis
    Invitation = Invitation
    Organization = Organization
    Profile = Profile
    Report = Report
    Rule = Rule
    Sample = Sample
    UserAccessInfo = UserAccessInfo
