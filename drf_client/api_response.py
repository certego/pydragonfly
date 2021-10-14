import requests
import json


class APIResponse(object):
    def __init__(self, response: requests.Response):
        self._response = response
        self.url = response.url
        self.code = response.status_code
        self.headers = response.headers
        try:
            self._handle_json_response()
        except json.JSONDecodeError:
            self._handle_generic_response()

    def _handle_json_response(self) -> None:
        self.data: dict = self._response.json()

    def _handle_generic_response(self) -> None:
        content_disposition: str = self._response.headers.get("Content-Disposition", "")
        _split_names = content_disposition.split(r"attachment; filename=")
        if len(_split_names) == 2:
            # case: file attachment
            self.file_name: str = _split_names[1]
            self.raw: bytes = self._response.content

    def __repr__(self) -> str:
        return f'APIResponse("{self.url}", {self.code})'
