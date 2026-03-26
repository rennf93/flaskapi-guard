from collections.abc import Mapping, MutableMapping
from typing import Any, cast

from flask import Response


class FlaskGuardRequest:
    def __init__(self, request: Any) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        result: str = self._request.path
        return result

    @property
    def url_scheme(self) -> str:
        result: str = self._request.scheme
        return result

    @property
    def url_full(self) -> str:
        result: str = self._request.url
        return result

    def url_replace_scheme(self, scheme: str) -> str:
        url: str = self._request.url
        if url.startswith("http://"):
            return scheme + "://" + url[7:]
        if url.startswith("https://"):
            return scheme + "://" + url[8:]
        return url

    @property
    def method(self) -> str:
        result: str = self._request.method
        return result

    @property
    def client_host(self) -> str | None:
        result: str | None = self._request.remote_addr
        return result

    @property
    def headers(self) -> Mapping[str, str]:
        result: Mapping[str, str] = self._request.headers
        return result

    @property
    def query_params(self) -> Mapping[str, str]:
        result: Mapping[str, str] = self._request.args
        return result

    def body(self) -> bytes:
        result: bytes = self._request.get_data()
        return result

    @property
    def state(self) -> Any:
        from flask import g

        return g

    @property
    def scope(self) -> dict[str, Any]:
        return {"environ": self._request.environ}


class FlaskGuardResponse:
    def __init__(self, response: Response) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return cast(MutableMapping[str, str], self._response.headers)

    @property
    def body(self) -> bytes | None:
        return self._response.get_data()


class FlaskResponseFactory:
    def create_response(self, content: str, status_code: int) -> FlaskGuardResponse:
        return FlaskGuardResponse(Response(content, status=status_code))

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> FlaskGuardResponse:
        from flask import redirect

        return FlaskGuardResponse(cast(Response, redirect(url, code=status_code)))


def unwrap_response(guard_response: Any) -> Response:
    if isinstance(guard_response, FlaskGuardResponse):
        return guard_response._response
    return Response(
        guard_response.body,
        status=guard_response.status_code,
        headers=dict(guard_response.headers),
    )
