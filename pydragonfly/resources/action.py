from drf_client import (
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    PaginationAPIResourceMixin,
)


class Action(
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    PaginationAPIResourceMixin,
):
    OBJECT_NAME = "api.action"
    EXPANDABLE_FIELDS = {
        "retrieve": ["user"],
        "list": ["user"],
    }
    ORDERING_FIELDS = []
