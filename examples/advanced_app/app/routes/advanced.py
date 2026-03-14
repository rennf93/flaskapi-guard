from flask import Blueprint, jsonify, request

from app.models import message_response
from app.security import guard

bp = Blueprint("advanced", __name__, url_prefix="/advanced")


@bp.route("/business-hours")
@guard.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
def business_hours_only():
    return jsonify(
        message_response(
            "Access granted during business hours",
            details={"hours": "09:00-17:00 UTC"},
        )
    )


@bp.route("/weekend-only")
@guard.time_window(start_time="00:00", end_time="23:59", timezone="UTC")
def weekend_endpoint():
    return jsonify(
        message_response(
            "Weekend access endpoint",
            details={
                "note": "Implement weekend check in time_window",
            },
        )
    )


@bp.route("/honeypot", methods=["POST"])
@guard.honeypot_detection(["honeypot_field", "trap_input", "hidden_field"])
def honeypot_detection():
    return jsonify(
        message_response(
            "Human user verified",
            details={"honeypot_status": "clean"},
        )
    )


@bp.route("/suspicious-patterns")
@guard.suspicious_detection(enabled=True)
def detect_suspicious_patterns():
    query = request.args.get("query")
    return jsonify(
        message_response(
            "No suspicious patterns detected",
            details={"query": query},
        )
    )
