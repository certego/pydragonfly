from typing import Optional, Generator

from .api_response import APIResponse
from .types import Toid, TParams


class RetrievableAPIResourceMixin:
    @classmethod
    def retrieve(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id)
        response = cls._request("GET", url=url, params=params)
        return response


class ListableAPIResourceMixin:
    @classmethod
    def list(
        cls,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.class_url()
        response = cls._request("GET", url=url, params=params)
        return response


class CreateableAPIResourceMixin:
    @classmethod
    def create(
        cls,
        data: Optional[dict] = None,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.class_url()
        response = cls._request("POST", url=url, data=data, params=params)
        return response


class UpdateableAPIResourceMixin:
    @classmethod
    def update(
        cls,
        object_id: Toid,
        data: Optional[dict] = None,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id)
        response = cls._request("PUT", url=url, data=data, params=params)
        return response


class DeletableAPIResourceMixin:
    @classmethod
    def delete(
        cls,
        object_id: Toid,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.instance_url(object_id)
        response = cls._request("DELETE", url=url, params=params)
        return response


class PaginationAPIResourceMixin:
    """
    Should be used with ``ListableAPIResourceMixin``.
    """

    @classmethod
    def auto_paging_iter(
        cls, **params: Optional[TParams]
    ) -> Generator[APIResponse, None, None]:
        response = cls.list(**params, page=1)
        yield response  # yield first page
        total_pages = response.data.get("total_pages", 1)
        for page in range(2, total_pages + 1):
            response = cls.list(**params, page=page)
            yield response  # yield subsequent pages


class SingletonAPIResourceMixin:
    @classmethod
    def get(
        cls,
        **params: Optional[TParams],
    ) -> APIResponse:
        url = cls.class_url()
        response = cls._request("GET", url=url, params=params)
        return response

    @classmethod
    def class_url(cls) -> str:
        if cls == SingletonAPIResourceMixin:
            raise NotImplementedError(
                "SingletonAPIResource is an abstract class."
                " You should perform actions on its subclasses ."
            )
        # Namespaces are separated in object names with periods (.) and in URLs
        # with forward slashes (/), so replace the former with the latter.
        base = cls.OBJECT_NAME.replace(".", "/")
        return base

    @classmethod
    def instance_url(cls) -> str:
        return cls.class_url()
