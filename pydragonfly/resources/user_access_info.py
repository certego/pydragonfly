from drf_client import (
    APIResource,
    SingletonAPIResourceMixin,
)


class UserAccessInfo(
    APIResource,
    SingletonAPIResourceMixin,
):
    """
    Note: ``delete`` and ``leave`` methods are
    intentionally not provided to avoid accidents.
    Please use the GUI for those operations.
    """

    OBJECT_NAME = "api.me.access"
    EXPANDABLE_FIELDS = {
        "retrieve": [],
        "list": [],
    }
    ORDERING_FIELDS = []
