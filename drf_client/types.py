from typing import TypedDict, List, Dict, Union
from typing_extensions import Literal

TRequestMethods = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]

Toid = Union[str, int]

TExpandableFields = TypedDict(
    "TExpandableFields", {"retrieve": List[str], "list": List[str]}
)

THeaders = Dict[str, str]


class TParams(TypedDict, total=False):
    fields: List[str]
    omit: List[str]
    expand: List[str]
    ordering: List[str]
    paginate: bool
    page: int
    page_size: int
