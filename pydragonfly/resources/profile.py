from drf_client import (
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    UpdateableAPIResourceMixin,
    PaginationAPIResourceMixin,
)


class Profile(
    APIResource,
    RetrievableAPIResourceMixin,
    ListableAPIResourceMixin,
    CreateableAPIResourceMixin,
    UpdateableAPIResourceMixin,
    PaginationAPIResourceMixin,
):
    OBJECT_NAME = "api.profile"
    EXPANDABLE_FIELDS = {
        "retrieve": ["user", "permissions"],
        "list": ["user", "permissions"],
    }
    ORDERING_FIELDS = [
        "filename",
        "created_at",
    ]
