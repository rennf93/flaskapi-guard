import logging
import os
from datetime import datetime, timezone
from ipaddress import ip_address

from flask import (
    Blueprint,
    Flask,
    Response,
    jsonify,
    make_response,
    request,
)

from flaskapi_guard import (
    FlaskAPIGuard,
    SecurityConfig,
    SecurityDecorator,
    ip_ban_manager,
)
from flaskapi_guard.handlers.behavior_handler import BehaviorRule
from flaskapi_guard.handlers.cloud_handler import cloud_handler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def custom_request_check(req):
    if req.args.get("debug") == "true":
        client_host = req.remote_addr or "unknown"
        logger.warning(f"Blocked debug request from {client_host}")
        return Response(
            response='{"detail": "Debug mode not allowed"}',
            status=403,
            content_type="application/json",
        )
    return None


def custom_response_modifier(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp


security_config = SecurityConfig(
    whitelist=["127.0.0.1", "::1", "10.0.0.0/8"],
    blacklist=["192.168.100.0/24"],
    trusted_proxies=["127.0.0.1", "10.0.0.0/8"],
    trusted_proxy_depth=2,
    trust_x_forwarded_proto=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    blocked_user_agents=["badbot", "evil-crawler", "sqlmap"],
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_penetration_detection=True,
    enable_redis=True,
    redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
    redis_prefix=os.environ.get("REDIS_PREFIX", "flaskapi_guard:"),
    enforce_https=False,
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
    cloud_ip_refresh_interval=1800,
    log_format="json",
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'strict-dynamic'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": [
                "'self'",
                "https://fonts.gstatic.com",
            ],
            "connect-src": ["'self'"],
        },
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False,
        },
        "frame_options": "SAMEORIGIN",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        ),
        "custom": {
            "X-App-Name": "FlaskAPI-Guard-Example",
            "X-Security-Contact": "security@example.com",
        },
    },
    enable_cors=True,
    cors_allow_origins=[
        "http://localhost:3000",
        "https://example.com",
    ],
    cors_allow_methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
    ],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Total-Count"],
    cors_max_age=3600,
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    custom_log_file="security.log",
    exclude_paths=["/favicon.ico", "/static", "/health"],
    passive_mode=False,
)

app = Flask(__name__)
guard_decorator = SecurityDecorator(security_config)
guard = FlaskAPIGuard(app, config=security_config)
guard.set_decorator_handler(guard_decorator)


basic_bp = Blueprint("basic", __name__, url_prefix="/basic")


@basic_bp.route("/")
def basic_root():
    return jsonify({"message": "Basic features endpoint"})


@basic_bp.route("/ip")
def basic_ip():
    client_ip = request.remote_addr or "unknown"
    try:
        ip_obj = ip_address(client_ip)
        ip_info = {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
        }
    except ValueError:
        ip_info = {"ip": client_ip, "error": "Invalid IP"}
    return jsonify(
        {
            "message": "Client IP information",
            "details": ip_info,
        }
    )


@basic_bp.route("/health")
def basic_health():
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@basic_bp.route("/echo", methods=["POST"])
def basic_echo():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "Echo response",
            "details": {
                "received_data": data,
                "headers": dict(request.headers),
                "method": request.method,
                "url": request.url,
            },
        }
    )


access_bp = Blueprint("access", __name__, url_prefix="/access")


@access_bp.route("/ip-whitelist")
@guard_decorator.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
def access_ip_whitelist():
    return jsonify(
        {
            "message": "IP whitelist access granted",
            "details": {
                "allowed_ranges": [
                    "127.0.0.1",
                    "10.0.0.0/8",
                ]
            },
        }
    )


@access_bp.route("/ip-blacklist")
@guard_decorator.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
def access_ip_blacklist():
    return jsonify(
        {
            "message": "IP blacklist check passed",
            "details": {
                "blocked_ranges": [
                    "192.168.1.0/24",
                    "172.16.0.0/12",
                ]
            },
        }
    )


@access_bp.route("/country-block")
@guard_decorator.block_countries(["CN", "RU", "KP"])
def access_country_block():
    return jsonify(
        {
            "message": "Country block check passed",
            "details": {"blocked_countries": ["CN", "RU", "KP"]},
        }
    )


@access_bp.route("/country-allow")
@guard_decorator.allow_countries(["US", "CA", "GB", "AU"])
def access_country_allow():
    return jsonify(
        {
            "message": "Country allow check passed",
            "details": {"allowed_countries": ["US", "CA", "GB", "AU"]},
        }
    )


@access_bp.route("/no-cloud")
@guard_decorator.block_clouds()
def access_no_cloud():
    return jsonify(
        {
            "message": "Cloud provider check passed",
            "details": {"all_cloud_providers_blocked": True},
        }
    )


@access_bp.route("/no-aws")
@guard_decorator.block_clouds(["AWS"])
def access_no_aws():
    return jsonify(
        {
            "message": "AWS cloud check passed",
            "details": {"blocked_providers": ["AWS"]},
        }
    )


@access_bp.route("/bypass-demo")
@guard_decorator.bypass(["rate_limit", "geo_check"])
def access_bypass_demo():
    return jsonify(
        {
            "message": "Security bypass demo",
            "details": {
                "bypassed_checks": [
                    "rate_limit",
                    "geo_check",
                ]
            },
        }
    )


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/https-only")
@guard_decorator.require_https()
def auth_https_only():
    return jsonify(
        {
            "message": "HTTPS verification passed",
            "details": {"protocol": "https"},
        }
    )


@auth_bp.route("/bearer-auth")
@guard_decorator.require_auth(type="bearer")
def auth_bearer():
    return jsonify(
        {
            "message": "Bearer authentication verified",
            "details": {"auth_type": "bearer"},
        }
    )


@auth_bp.route("/api-key")
@guard_decorator.api_key_auth(header_name="X-API-Key")
def auth_api_key():
    return jsonify(
        {
            "message": "API key authentication verified",
            "details": {"auth_type": "api_key"},
        }
    )


@auth_bp.route("/custom-headers")
@guard_decorator.require_headers(
    {
        "X-Custom-Header": "required-value",
        "X-Client-ID": "required-value",
    }
)
def auth_custom_headers():
    return jsonify(
        {
            "message": "Custom headers verified",
            "details": {
                "required_headers": [
                    "X-Custom-Header",
                    "X-Client-ID",
                ]
            },
        }
    )


rate_bp = Blueprint("rate", __name__, url_prefix="/rate")


@rate_bp.route("/custom-limit")
@guard_decorator.rate_limit(requests=5, window=60)
def rate_custom_limit():
    return jsonify(
        {
            "message": "Custom rate limit endpoint",
            "details": {
                "limit": 5,
                "window": "60 seconds",
            },
        }
    )


@rate_bp.route("/strict-limit")
@guard_decorator.rate_limit(requests=1, window=10)
def rate_strict_limit():
    return jsonify(
        {
            "message": "Strict rate limit endpoint",
            "details": {
                "limit": 1,
                "window": "10 seconds",
            },
        }
    )


@rate_bp.route("/geo-rate-limit")
@guard_decorator.geo_rate_limit(
    {
        "US": (100, 60),
        "CN": (10, 60),
        "RU": (20, 60),
        "*": (50, 60),
    }
)
def rate_geo_limit():
    return jsonify(
        {
            "message": "Geo-based rate limit endpoint",
            "details": {
                "rates": {
                    "US": "100/60s",
                    "CN": "10/60s",
                    "RU": "20/60s",
                    "default": "50/60s",
                }
            },
        }
    )


behavior_bp = Blueprint("behavior", __name__, url_prefix="/behavior")


@behavior_bp.route("/usage-monitor")
@guard_decorator.usage_monitor(max_calls=10, window=300, action="log")
def behavior_usage_monitor():
    return jsonify(
        {
            "message": "Usage monitored endpoint",
            "details": {
                "max_calls": 10,
                "window": "300 seconds",
                "action": "log",
            },
        }
    )


@behavior_bp.route("/return-monitor/<int:status_code>")
@guard_decorator.return_monitor(
    pattern="404",
    max_occurrences=3,
    window=60,
    action="ban",
)
def behavior_return_monitor(status_code):
    if status_code == 404:
        return jsonify({"detail": "Not found"}), 404
    return jsonify(
        {
            "message": "Return monitor endpoint",
            "details": {
                "status_code": status_code,
                "monitored_pattern": "404",
            },
        }
    )


@behavior_bp.route("/suspicious-frequency")
@guard_decorator.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
def behavior_suspicious_frequency():
    return jsonify(
        {
            "message": "Suspicious frequency endpoint",
            "details": {
                "max_frequency": 0.5,
                "window": "10 seconds",
                "action": "throttle",
            },
        }
    )


@behavior_bp.route("/behavior-rules", methods=["POST"])
@guard_decorator.behavior_analysis(
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
def behavior_rules():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "Behavior analysis endpoint",
            "details": {
                "received_data": data,
                "rules": [
                    {
                        "type": "frequency",
                        "threshold": 10,
                        "action": "throttle",
                    },
                    {
                        "type": "return_pattern",
                        "pattern": "404",
                        "action": "ban",
                    },
                ],
            },
        }
    )


headers_bp = Blueprint("headers", __name__, url_prefix="/headers")


@headers_bp.route("/")
def headers_root():
    return jsonify(
        {
            "message": "Security headers information",
            "details": {
                "headers": [
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                    "Permissions-Policy",
                ],
                "description": (
                    "Security headers are automatically applied to all responses"
                ),
            },
        }
    )


@headers_bp.route("/test-page")
def headers_test_page():
    html = """<!DOCTYPE html>
<html>
<head>
    <title>FlaskAPI Guard Security Headers Demo</title>
    <style>
        body { font-family: Arial, sans-serif;
               max-width: 800px; margin: 0 auto;
               padding: 20px; }
        .header-info { background: #f0f0f0;
                       padding: 10px; margin: 5px 0;
                       border-radius: 5px; }
    </style>
</head>
<body>
    <h1>FlaskAPI Guard Security Headers Demo</h1>
    <p>Check browser DevTools to see security headers.</p>
    <div id="headers"></div>
    <script>
        document.getElementById('headers').textContent =
            'Headers loaded via CSP-compliant script.';
    </script>
</body>
</html>"""
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


@headers_bp.route("/csp-report", methods=["POST"])
def headers_csp_report():
    data = request.get_json(silent=True) or {}
    logger.warning(f"CSP Violation Report: {data}")
    return jsonify(
        {
            "message": "CSP violation report received",
            "details": data,
        }
    )


@headers_bp.route("/frame-test")
def headers_frame_test():
    html = """<!DOCTYPE html>
<html>
<head><title>Frame Test</title></head>
<body>
    <h1>Frame Test Page</h1>
    <p>This page tests X-Frame-Options header.</p>
    <iframe src="/headers/" width="100%"
            height="300"></iframe>
</body>
</html>"""
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


@headers_bp.route("/hsts-info")
def headers_hsts_info():
    hsts_config = security_config.security_headers.get("hsts", {})
    return jsonify(
        {
            "message": "HSTS configuration",
            "details": {
                "max_age": hsts_config.get("max_age", 31536000),
                "include_subdomains": hsts_config.get("include_subdomains", True),
                "preload": hsts_config.get("preload", False),
            },
        }
    )


@headers_bp.route("/security-analysis")
def headers_security_analysis():
    req_headers = dict(request.headers)
    analysis = {
        "has_authorization": "Authorization" in req_headers,
        "has_user_agent": "User-Agent" in req_headers,
        "has_accept": "Accept" in req_headers,
        "has_content_type": "Content-Type" in req_headers,
        "has_origin": "Origin" in req_headers,
        "has_referer": "Referer" in req_headers,
        "total_headers": len(req_headers),
    }
    return jsonify(
        {
            "message": "Request header analysis",
            "details": {
                "analysis": analysis,
                "headers_received": req_headers,
            },
        }
    )


content_bp = Blueprint("content", __name__, url_prefix="/content")


@content_bp.route("/no-bots")
@guard_decorator.block_user_agents(["bot", "crawler", "spider", "scraper"])
def content_no_bots():
    return jsonify(
        {
            "message": "Bot-free zone",
            "details": {
                "blocked_agents": [
                    "bot",
                    "crawler",
                    "spider",
                    "scraper",
                ]
            },
        }
    )


@content_bp.route("/json-only", methods=["POST"])
@guard_decorator.content_type_filter(["application/json"])
def content_json_only():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "JSON content accepted",
            "details": {"received_data": data},
        }
    )


@content_bp.route("/size-limit", methods=["POST"])
@guard_decorator.max_request_size(1024 * 100)
def content_size_limit():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "Request within size limit",
            "details": {
                "max_size": "100KB",
                "received_data": data,
            },
        }
    )


@content_bp.route("/referrer-check")
@guard_decorator.require_referrer(["https://example.com", "https://app.example.com"])
def content_referrer_check():
    return jsonify(
        {
            "message": "Referrer check passed",
            "details": {
                "allowed_referrers": [
                    "https://example.com",
                    "https://app.example.com",
                ]
            },
        }
    )


def custom_validator(req):
    user_agent = req.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return Response(
            response=('{"detail": "Suspicious user agent detected"}'),
            status=403,
            content_type="application/json",
        )
    return None


@content_bp.route("/custom-validation")
@guard_decorator.custom_validation(custom_validator)
def content_custom_validation():
    return jsonify(
        {
            "message": "Custom validation passed",
            "details": {"validator": "user_agent_check"},
        }
    )


advanced_bp = Blueprint("advanced", __name__, url_prefix="/advanced")


@advanced_bp.route("/business-hours")
@guard_decorator.time_window(
    start_time="09:00",
    end_time="17:00",
    timezone="UTC",
)
def advanced_business_hours():
    return jsonify(
        {
            "message": "Business hours access granted",
            "details": {
                "window": "09:00-17:00 UTC",
                "current_time": datetime.now(timezone.utc).strftime("%H:%M UTC"),
            },
        }
    )


@advanced_bp.route("/weekend-only")
@guard_decorator.time_window(
    start_time="00:00",
    end_time="23:59",
    timezone="UTC",
)
def advanced_weekend_only():
    return jsonify(
        {
            "message": "Weekend access granted",
            "details": {
                "window": "00:00-23:59 UTC",
                "current_time": datetime.now(timezone.utc).strftime("%H:%M UTC"),
            },
        }
    )


@advanced_bp.route("/honeypot", methods=["POST"])
@guard_decorator.honeypot_detection(["honeypot_field", "trap_input", "hidden_field"])
def advanced_honeypot():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "Honeypot check passed",
            "details": {
                "received_data": data,
                "honeypot_fields": [
                    "honeypot_field",
                    "trap_input",
                    "hidden_field",
                ],
            },
        }
    )


@advanced_bp.route("/suspicious-patterns")
@guard_decorator.suspicious_detection(enabled=True)
def advanced_suspicious_patterns():
    query = request.args.get("q", "")
    return jsonify(
        {
            "message": "Suspicious pattern check passed",
            "details": {"query": query},
        }
    )


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/unban-ip", methods=["POST"])
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
def admin_unban_ip():
    data = request.get_json(silent=True) or {}
    ip_to_unban = data.get("ip")
    if not ip_to_unban:
        return jsonify({"detail": "IP address required"}), 400
    ip_ban_manager.unban_ip(ip_to_unban)
    return jsonify(
        {
            "message": f"IP {ip_to_unban} has been unbanned",
            "details": {"unbanned_ip": ip_to_unban},
        }
    )


@admin_bp.route("/stats")
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
def admin_stats():
    return jsonify(
        {
            "message": "Security statistics",
            "details": {
                "total_requests": 0,
                "blocked_requests": 0,
                "rate_limited": 0,
                "banned_ips": 0,
                "active_rules": 0,
                "uptime": "unknown",
            },
        }
    )


@admin_bp.route("/clear-cache", methods=["POST"])
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
def admin_clear_cache():
    return jsonify(
        {
            "message": "Cache cleared successfully",
            "details": {"cleared_at": datetime.now(timezone.utc).isoformat()},
        }
    )


@admin_bp.route("/emergency-mode", methods=["PUT"])
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
def admin_emergency_mode():
    data = request.get_json(silent=True) or {}
    enable = data.get("enable", False)
    return jsonify(
        {
            "message": (
                "Emergency mode enabled" if enable else "Emergency mode disabled"
            ),
            "details": {"emergency_mode": enable},
        }
    )


@admin_bp.route("/cloud-status")
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
def cloud_status():
    last_updated = {}
    for provider, dt in cloud_handler.last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return jsonify(
        {
            "message": "Cloud provider IP range status",
            "details": {
                "refresh_interval": (security_config.cloud_ip_refresh_interval),
                "providers": last_updated,
            },
        }
    )


test_bp = Blueprint("test", __name__, url_prefix="/test")


@test_bp.route("/xss-test", methods=["POST"])
def test_xss():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "XSS test endpoint",
            "details": {"received_data": data},
        }
    )


@test_bp.route("/sql-injection")
def test_sql_injection():
    query = request.args.get("query", "")
    return jsonify(
        {
            "message": "SQL injection test endpoint",
            "details": {"query_received": query},
        }
    )


@test_bp.route("/path-traversal/<path:file_path>")
def test_path_traversal(file_path):
    return jsonify(
        {
            "message": "Path traversal test endpoint",
            "details": {"path_received": file_path},
        }
    )


@test_bp.route("/command-injection", methods=["POST"])
def test_command_injection():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "Command injection test endpoint",
            "details": {"received_data": data},
        }
    )


@test_bp.route("/mixed-attack", methods=["POST"])
def test_mixed_attack():
    data = request.get_json(silent=True) or {}
    return jsonify(
        {
            "message": "Mixed attack test endpoint",
            "details": {
                "received_fields": list(data.keys()),
                "field_count": len(data),
            },
        }
    )


@app.route("/")
def root():
    return jsonify(
        {
            "message": "FlaskAPI Guard Example Application",
            "details": {
                "version": "1.0.0",
                "endpoints": {
                    "/basic": "Basic features",
                    "/access": "Access control",
                    "/auth": "Authentication",
                    "/rate": "Rate limiting",
                    "/behavior": "Behavioral analysis",
                    "/headers": "Security headers",
                    "/content": "Content filtering",
                    "/advanced": "Advanced features",
                    "/admin": "Administration",
                    "/test": "Security testing",
                },
            },
        }
    )


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.errorhandler(404)
def not_found(e):
    return jsonify({"detail": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"detail": "Internal server error"}), 500


app.register_blueprint(basic_bp)
app.register_blueprint(access_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(rate_bp)
app.register_blueprint(behavior_bp)
app.register_blueprint(headers_bp)
app.register_blueprint(content_bp)
app.register_blueprint(advanced_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(test_bp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
