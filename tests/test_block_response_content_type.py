import os
from typing import cast

from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager

from flaskapi_guard.extension import FlaskAPIGuard

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))

BLOCKED_IP = "203.0.113.10"


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        geo_ip_handler=cast(GeoIPHandler, IPInfoManager(IPINFO_TOKEN)),
        blacklist=(BLOCKED_IP,),
        enable_rate_limiting=False,
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
        **overrides,  # type: ignore[arg-type]
    )


def _blocked_response_headers(config: SecurityConfig) -> tuple[int, str, str]:
    app = Flask(__name__)
    FlaskAPIGuard(app, config=config)

    @app.route("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    with app.test_client() as client:
        response = client.get("/ping", headers={"X-Forwarded-For": BLOCKED_IP})
    return (
        response.status_code,
        response.headers.get("Content-Type", ""),
        response.headers.get("X-Content-Type-Options", ""),
    )


def test_block_response_is_plain_text() -> None:
    status_code, content_type, nosniff = _blocked_response_headers(_config())
    assert (status_code, content_type, nosniff) == (
        403,
        "text/plain; charset=utf-8",
        "nosniff",
    )


def test_custom_error_message_is_plain_text() -> None:
    config = _config(custom_error_responses={403: "Access denied"})

    status_code, content_type, _nosniff = _blocked_response_headers(config)

    assert (status_code, content_type) == (403, "text/plain; charset=utf-8")


def test_response_modifier_can_still_set_its_own_content_type() -> None:
    def problem_json(response: GuardResponse) -> GuardResponse:
        response.headers["Content-Type"] = "application/problem+json"
        return response

    config = _config(custom_response_modifier=problem_json)

    status_code, content_type, _nosniff = _blocked_response_headers(config)

    assert (status_code, content_type) == (403, "application/problem+json")
