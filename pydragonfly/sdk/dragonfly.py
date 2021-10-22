import logging
from django_rest_client import APIClient
from django_rest_client.types import THeaders

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
