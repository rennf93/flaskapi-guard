from flask import Blueprint, jsonify

from app.models import message_response
from app.security import guard

bp = Blueprint("access", __name__, url_prefix="/access")


@bp.route("/ip-whitelist")
@guard.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
def ip_whitelist_only():
    return jsonify(message_response("Access granted from whitelisted IP"))


@bp.route("/ip-blacklist")
@guard.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
def ip_blacklist_demo():
    return jsonify(message_response("Access granted - not blacklisted"))


@bp.route("/country-block")
@guard.block_countries(["CN", "RU", "KP"])
def block_specific_countries():
    return jsonify(message_response("Access granted - country not blocked"))


@bp.route("/country-allow")
@guard.allow_countries(["US", "CA", "GB", "AU"])
def allow_specific_countries():
    return jsonify(message_response("Access granted from allowed country"))


@bp.route("/no-cloud")
@guard.block_clouds()
def block_all_clouds():
    return jsonify(message_response("Access granted - not from cloud"))


@bp.route("/no-aws")
@guard.block_clouds(["AWS"])
def block_aws_only():
    return jsonify(message_response("Access granted - not from AWS"))


@bp.route("/bypass-demo")
@guard.bypass(["rate_limit", "geo_check"])
def bypass_specific_checks():
    return jsonify(
        message_response(
            "This endpoint bypasses rate limiting and geo checks",
            details={
                "bypassed_checks": ["rate_limit", "geo_check"],
            },
        )
    )
