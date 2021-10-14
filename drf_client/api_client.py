import inspect
import requests
import logging
from abc import ABCMeta, abstractmethod

from .api_response import APIResponse
from .api_resource import APIResource
from .exceptions import APIClientException
from .types import TRequestMethods, THeaders


class APIClient(metaclass=ABCMeta):
    _logger: logging.Logger = logging.getLogger(__name__)

    def __init__(
        self,
        token: str,
        certificate: str = None,
        logger: logging.Logger = None,
    ):
        self.__token = token
        self.__certificate = certificate
        if logger is not None:
            self._logger = logger

        # hook
        self.__post__init__()

    def __post__init__(self) -> None:
        """
        Hook method for post ``__init__`` initialization.
        Always call ``super()`` if overwriting this.
        """
        # register resources
        for key, value in self.__class__.__dict__.items():
            if inspect.isclass(value) and issubclass(value, APIResource):
                klass = value
                klass._request = self._request
                self.__setattr__(key, klass)

    @property
    @abstractmethod
    def _server_url(self) -> str:
        raise NotImplementedError()

    @property
    def _headers(self) -> THeaders:
        return {"User-Agent": "APIClient"}

    @property
    def __session(self) -> requests.Session:
        """
        Internal use only.
        """
        if not hasattr(self, "__cached_session"):
            session = requests.Session()
            if self.__certificate is not None:
                session.verify = self.__certificate
            session.headers.update(
                {
                    "Authorization": f"Token {self.__token}",
                    **self._headers,
                }
            )
            self.__cached_session = session

        return self.__cached_session

    def _request(
        self,
        method: TRequestMethods,
        url: str,
        *args,
        **kwargs,
    ) -> APIResponse:
        """
        For internal use only.
        """
        full_url = f"{self._server_url}/{url}"
        response: requests.Response = None
        try:
            response = self.__session.request(
                method=method, url=full_url, *args, **kwargs
            )
            self._logger.debug(
                msg=(response.url, response.status_code, response.content)
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise APIClientException(e, response=response)

        return APIResponse(response)
