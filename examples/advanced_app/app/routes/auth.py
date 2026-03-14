from flask import Blueprint, jsonify, request

from app.models import auth_response, message_response
from app.security import guard

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/https-only")
@guard.require_https()
def https_required_endpoint():
    return jsonify(
        message_response(
            "HTTPS connection verified",
            details={"protocol": request.scheme},
        )
    )


@bp.route("/bearer-auth")
@guard.require_auth(type="bearer")
def bearer_authentication():
    return jsonify(
        auth_response(
            authenticated=True,
            user="example_user",
            method="bearer",
            permissions=["read", "write"],
        )
    )


@bp.route("/api-key")
@guard.api_key_auth(header_name="X-API-Key")
def api_key_authentication():
    return jsonify(
        auth_response(
            authenticated=True,
            user="api_user",
            method="api_key",
            permissions=["read"],
        )
    )


@bp.route("/custom-headers")
@guard.require_headers(
    {
        "X-Custom-Header": "required-value",
        "X-Client-ID": "required-value",
    }
)
def require_custom_headers():
    return jsonify(
        message_response(
            "Required headers verified",
            details={"headers": dict(request.headers)},
        )
    )
