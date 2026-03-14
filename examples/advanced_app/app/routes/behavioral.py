from flask import Blueprint, jsonify

from app.models import message_response
from app.security import guard
from flaskapi_guard.handlers.behavior_handler import BehaviorRule

bp = Blueprint("behavior", __name__, url_prefix="/behavior")


@bp.route("/usage-monitor")
@guard.usage_monitor(max_calls=10, window=300, action="log")
def monitor_usage_patterns():
    return jsonify(
        message_response(
            "Usage monitoring active",
            details={"monitoring": "10 calls per 5 minutes"},
        )
    )


@bp.route("/return-monitor/<int:status_code>")
@guard.return_monitor(pattern="404", max_occurrences=3, window=60, action="ban")
def monitor_return_patterns(status_code: int):
    if status_code == 404:
        return jsonify({"detail": "Not found"}), 404
    return jsonify(message_response(f"Status code: {status_code}"))


@bp.route("/suspicious-frequency")
@guard.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
def detect_suspicious_frequency():
    return jsonify(
        message_response(
            "Frequency monitoring active",
            details={
                "max_frequency": "1 request per 2 seconds",
            },
        )
    )


@bp.route("/behavior-rules", methods=["POST"])
@guard.behavior_analysis(
    [
        BehaviorRule(
            rule_type="frequency",
            threshold=10,
            window=60,
            action="throttle",
        ),
        BehaviorRule(
            rule_type="return_pattern",
            pattern="404",
            threshold=5,
            window=60,
            action="ban",
        ),
    ]
)
def complex_behavior_analysis():
    return jsonify(
        message_response(
            "Complex behavior analysis active",
            details={"rules": ["frequency", "return_pattern"]},
        )
    )
