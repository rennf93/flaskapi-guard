from datetime import datetime, timezone
from typing import Any


def message_response(
    message: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {"message": message}
    if details is not None:
        result["details"] = details
    return result


def ip_info_response(
    ip: str,
    country: str | None = None,
    city: str | None = None,
    region: str | None = None,
    is_vpn: bool | None = None,
    is_cloud: bool | None = None,
    cloud_provider: str | None = None,
) -> dict[str, Any]:
    return {
        "ip": ip,
        "country": country,
        "city": city,
        "region": region,
        "is_vpn": is_vpn,
        "is_cloud": is_cloud,
        "cloud_provider": cloud_provider,
    }


def health_response(status: str = "healthy") -> dict[str, Any]:
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def stats_response(
    total_requests: int,
    blocked_requests: int,
    banned_ips: list[str],
    rate_limited_ips: dict[str, int],
    suspicious_activities: list[dict[str, Any]],
    active_rules: dict[str, Any],
) -> dict[str, Any]:
    return {
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "banned_ips": banned_ips,
        "rate_limited_ips": rate_limited_ips,
        "suspicious_activities": suspicious_activities,
        "active_rules": active_rules,
    }


def error_response(detail: str, error_code: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if error_code:
        result["error_code"] = error_code
    return result


def auth_response(
    authenticated: bool,
    user: str | None,
    method: str,
    permissions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "authenticated": authenticated,
        "user": user,
        "method": method,
        "permissions": permissions or [],
    }
