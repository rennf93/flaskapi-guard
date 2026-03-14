from ipaddress import ip_address
from typing import Any

from flask import Blueprint, jsonify, request

from app.models import health_response, ip_info_response, message_response

bp = Blueprint("basic", __name__, url_prefix="/basic")


@bp.route("/")
def basic_root():
    return jsonify(message_response("Basic features endpoint"))


@bp.route("/ip")
def get_ip_info():
    client_ip = "unknown"
    if request.remote_addr:
        try:
            client_ip = str(ip_address(request.remote_addr))
        except ValueError:
            client_ip = request.remote_addr

    return jsonify(
        ip_info_response(
            ip=client_ip,
            country="US",
            city="Example City",
            region="Example Region",
            is_vpn=False,
            is_cloud=False,
        )
    )


@bp.route("/health")
def health_check():
    return jsonify(health_response("healthy"))


@bp.route("/echo", methods=["POST"])
def echo_request():
    data: dict[str, Any] = request.get_json(silent=True) or {}
    return jsonify(
        message_response(
            "Echo response",
            details={
                "data": data,
                "headers": dict(request.headers),
                "method": request.method,
                "url": request.url,
            },
        )
    )
