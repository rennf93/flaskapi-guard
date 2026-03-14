import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from app.models import message_response, stats_response
from app.security import guard
from flaskapi_guard.handlers.cloud_handler import cloud_handler

logger = logging.getLogger(__name__)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/unban-ip", methods=["POST"])
@guard.require_ip(whitelist=["127.0.0.1"])
def unban_ip_address():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    logger.info(f"Unbanning IP: {ip}")
    return jsonify(
        message_response(
            f"IP {ip} has been unbanned",
            details={"action": "unban", "ip": ip},
        )
    )


@bp.route("/stats")
@guard.require_ip(whitelist=["127.0.0.1"])
def get_security_stats():
    return jsonify(
        stats_response(
            total_requests=1500,
            blocked_requests=75,
            banned_ips=["192.168.1.100", "10.0.0.50"],
            rate_limited_ips={
                "192.168.1.200": 5,
                "172.16.0.10": 3,
            },
            suspicious_activities=[
                {
                    "ip": "192.168.1.100",
                    "reason": "SQL injection attempt",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "ip": "10.0.0.50",
                    "reason": "Rapid requests",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            ],
            active_rules={
                "rate_limit": 30,
                "rate_window": 60,
                "auto_ban_threshold": 5,
                "blocked_countries": ["XX"],
                "blocked_clouds": ["AWS", "GCP", "Azure"],
            },
        )
    )


@bp.route("/clear-cache", methods=["POST"])
@guard.require_ip(whitelist=["127.0.0.1"])
def clear_security_cache():
    return jsonify(
        message_response(
            "Security caches cleared",
            details={
                "cleared": [
                    "rate_limit_cache",
                    "ip_ban_cache",
                    "geo_cache",
                ],
            },
        )
    )


@bp.route("/emergency-mode", methods=["PUT"])
@guard.require_ip(whitelist=["127.0.0.1"])
def toggle_emergency_mode():
    data = request.get_json(silent=True) or {}
    enable = data.get("enable", False)
    mode = "enabled" if enable else "disabled"
    return jsonify(
        message_response(
            f"Emergency mode {mode}",
            details={
                "emergency_mode": enable,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    )


@bp.route("/cloud-status")
@guard.require_ip(whitelist=["127.0.0.1"])
def cloud_status():
    from app.security import security_config

    last_updated = {}
    for provider, dt in cloud_handler.last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return jsonify(
        message_response(
            "Cloud provider IP range status",
            details={
                "refresh_interval": (security_config.cloud_ip_refresh_interval),
                "providers": last_updated,
            },
        )
    )
