"""
Flask API Guard Comprehensive Example
==================================

This example demonstrates the core features of the Flask API Guard security extension.

Features demonstrated:
- IP whitelisting/blacklisting with CIDR support
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Security headers
- CORS configuration
- Emergency mode

Run with: gunicorn examples.main:app --bind 0.0.0.0:8000 --reload
Or: flask --app examples.main run --debug
"""

import logging
import os
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

from flaskapi_guard import (
    FlaskAPIGuard,
    SecurityConfig,
    SecurityDecorator,
    ip_ban_manager,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

config = SecurityConfig(
    # Redis configuration
    enable_redis=True,
    redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
    redis_prefix=os.getenv("REDIS_PREFIX", "flaskapi_guard:"),
    # Rate limiting
    rate_limit=100,
    rate_limit_window=60,
    # IP management
    whitelist=["127.0.0.1", "::1"],
    blacklist=[],
    # Auto-banning
    auto_ban_threshold=10,
    auto_ban_duration=3600,
    enable_ip_banning=True,
    # Penetration detection
    enable_penetration_detection=True,
    # Logging
    log_suspicious_level="WARNING",
    log_request_level="INFO",
    # Security headers
    security_headers={
        "enabled": True,
        "csp": "default-src 'self'; script-src 'self'",
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False,
        },
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "1; mode=block",
        "referrer_policy": "strict-origin-when-cross-origin",
    },
    # CORS
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    cors_allow_headers=["*"],
    cors_allow_credentials=False,
    # Path exclusions
    exclude_paths=["/health", "/static", "/favicon.ico"],
    # HTTPS
    enforce_https=False,
)

# ============================================================================
# Application Setup
# ============================================================================

app = Flask(__name__)

# Initialize security decorator
security = SecurityDecorator(config)

# Initialize Flask API Guard
guard = FlaskAPIGuard(app, config=config)

# Connect decorator handler
guard.set_decorator_handler(security)


# ============================================================================
# Basic Routes
# ============================================================================


@app.route("/")
def root() -> Response:
    """Root endpoint."""
    return jsonify(
        {
            "message": "Flask API Guard Example API",
            "docs": "/api/info",
            "health": "/health",
        }
    )


@app.route("/health")
def health() -> Response:
    """Health check endpoint (excluded from security checks)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    return jsonify({"status": "healthy", "timestamp": timestamp})


@app.route("/api/info")
def api_info() -> Response:
    """API information endpoint."""
    return jsonify(
        {
            "name": "Flask API Guard Example",
            "version": "0.1.0",
            "security": "enabled",
            "features": [
                "rate_limiting",
                "ip_filtering",
                "penetration_detection",
                "behavioral_analysis",
                "security_headers",
            ],
        }
    )


# ============================================================================
# Rate Limited Routes
# ============================================================================


@app.route("/api/limited")
@security.rate_limit(requests=5, window=60)
def rate_limited() -> Response:
    """Rate-limited endpoint: 5 requests per minute."""
    return jsonify({"message": "This endpoint is rate limited", "limit": "5/minute"})


# ============================================================================
# Authentication Routes
# ============================================================================


@app.route("/api/protected")
@security.require_auth(type="bearer")
def protected() -> Response:
    """Protected endpoint requiring Bearer token."""
    return jsonify({"message": "Authenticated!", "user": "authenticated_user"})


@app.route("/api/api-key")
@security.api_key_auth("X-API-Key")
def api_key_protected() -> Response:
    """Endpoint requiring API key."""
    return jsonify({"message": "API key validated!"})


# ============================================================================
# Content Filtering Routes
# ============================================================================


@app.route("/api/json-only", methods=["POST"])
@security.content_type_filter(["application/json"])
def json_only() -> Response:
    """Endpoint that only accepts JSON content."""
    data = request.get_json(silent=True) or {}
    return jsonify({"received": data})


@app.route("/api/small-payload", methods=["POST"])
@security.max_request_size(1024)
def small_payload() -> Response:
    """Endpoint with 1KB request size limit."""
    return jsonify({"message": "Payload accepted"})


# ============================================================================
# Access Control Routes
# ============================================================================


@app.route("/api/local-only")
@security.require_ip(whitelist=["127.0.0.1", "::1", "10.0.0.0/8"])
def local_only() -> Response:
    """Endpoint restricted to local/private IPs."""
    return jsonify({"message": "Local access granted"})


# ============================================================================
# Advanced Routes
# ============================================================================


@app.route("/api/business-hours")
@security.time_window("09:00", "17:00", "UTC")
def business_hours() -> Response:
    """Endpoint available only during business hours (UTC)."""
    return jsonify(
        {
            "message": "Business hours endpoint",
            "current_time": datetime.now(timezone.utc).strftime("%H:%M"),
        }
    )


@app.route("/api/honeypot", methods=["POST"])
@security.honeypot_detection(["bot_trap", "hidden_field"])
def honeypot_endpoint() -> Response:
    """Endpoint with honeypot bot detection."""
    data = request.get_json(silent=True) or {}
    return jsonify({"message": "Human verified!", "data": data})


# ============================================================================
# Behavioral Analysis Routes
# ============================================================================


@app.route("/api/monitored")
@security.usage_monitor(max_calls=10, window=3600, action="log")
def monitored() -> Response:
    """Endpoint with behavioral usage monitoring."""
    return jsonify({"message": "Usage is being monitored"})


@app.route("/api/lootbox")
@security.return_monitor("win", max_occurrences=3, window=86400, action="ban")
def lootbox() -> Response:
    """Endpoint with return pattern monitoring."""
    import random

    result = random.choice(["win", "lose", "lose", "lose"])
    return jsonify({"result": {"status": result}})


# ============================================================================
# Admin Routes
# ============================================================================


@app.route("/api/admin/ban/<ip>", methods=["POST"])
@security.require_auth(type="bearer")
def ban_ip(ip: str) -> Response:
    """Ban an IP address."""
    ip_ban_manager.ban_ip(ip, duration=3600, reason="admin_ban")
    return jsonify({"message": f"IP {ip} banned for 1 hour"})


@app.route("/api/admin/unban/<ip>", methods=["POST"])
@security.require_auth(type="bearer")
def unban_ip(ip: str) -> Response:
    """Unban an IP address."""
    ip_ban_manager.unban_ip(ip)
    return jsonify({"message": f"IP {ip} unbanned"})


# ============================================================================
# Security Test Routes
# ============================================================================


@app.route("/api/test/xss")
def test_xss() -> Response:
    """Route to test XSS detection (try adding script tags in query params)."""
    query = request.args.get("q", "")
    return jsonify({"query": query, "message": "XSS detection is active"})


@app.route("/api/test/sqli")
def test_sqli() -> Response:
    """Route to test SQL injection detection."""
    query = request.args.get("q", "")
    return jsonify({"query": query, "message": "SQL injection detection is active"})


# ============================================================================
# Bypass Route
# ============================================================================


@app.route("/api/unprotected")
@security.bypass(["all"])
def unprotected() -> Response:
    """Endpoint that bypasses all security checks."""
    return jsonify({"message": "This endpoint has no security checks"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
