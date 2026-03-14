from flask import Blueprint, jsonify

from app.models import message_response
from app.security import guard

bp = Blueprint("rate", __name__, url_prefix="/rate")


@bp.route("/custom-limit")
@guard.rate_limit(requests=5, window=60)
def custom_rate_limit():
    return jsonify(
        message_response(
            "Custom rate limit endpoint",
            details={"limit": "5 requests per 60 seconds"},
        )
    )


@bp.route("/strict-limit")
@guard.rate_limit(requests=1, window=10)
def strict_rate_limit():
    return jsonify(
        message_response(
            "Strict rate limit endpoint",
            details={"limit": "1 request per 10 seconds"},
        )
    )


@bp.route("/geo-rate-limit")
@guard.geo_rate_limit(
    {
        "US": (100, 60),
        "CN": (10, 60),
        "RU": (20, 60),
        "*": (50, 60),
    }
)
def geographic_rate_limiting():
    return jsonify(
        message_response(
            "Geographic rate limiting applied",
            details={"description": "Rate limits vary by country"},
        )
    )
