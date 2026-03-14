from flask import Blueprint, Request, Response, jsonify, request

from app.models import message_response
from app.security import guard

bp = Blueprint("content", __name__, url_prefix="/content")


@bp.route("/no-bots")
@guard.block_user_agents(["bot", "crawler", "spider", "scraper"])
def block_bots():
    return jsonify(message_response("Human users only - bots blocked"))


@bp.route("/json-only", methods=["POST"])
@guard.content_type_filter(["application/json"])
def json_content_only():
    data = request.get_json(silent=True) or {}
    return jsonify(
        message_response(
            "JSON content received",
            details={"data": data},
        )
    )


@bp.route("/size-limit", methods=["POST"])
@guard.max_request_size(1024 * 100)
def limited_upload_size():
    return jsonify(
        message_response(
            "Data received within size limit",
            details={"size_limit": "100KB"},
        )
    )


@bp.route("/referrer-check")
@guard.require_referrer(["https://example.com", "https://app.example.com"])
def check_referrer():
    referrer = request.headers.get("referer", "No referrer")
    return jsonify(
        message_response(
            "Valid referrer",
            details={"referrer": referrer},
        )
    )


def custom_validator(req: Request) -> Response | None:
    user_agent = req.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return Response(
            response='{"detail": "Suspicious user agent"}',
            status=403,
            content_type="application/json",
        )
    return None


@bp.route("/custom-validation")
@guard.custom_validation(custom_validator)
def custom_content_validation():
    return jsonify(
        message_response(
            "Custom validation passed",
            details={"validator": "custom_validator"},
        )
    )
