import logging

from flask import Blueprint, jsonify, make_response, request

from app.models import message_response

logger = logging.getLogger(__name__)

bp = Blueprint("headers", __name__, url_prefix="/headers")


@bp.route("/")
def security_headers_info():
    return jsonify(
        message_response(
            "All responses include security headers",
            details={
                "headers": [
                    "X-Content-Type-Options: nosniff",
                    "X-Frame-Options: SAMEORIGIN",
                    "X-XSS-Protection: 1; mode=block",
                    "Strict-Transport-Security: max-age=31536000",
                    "Content-Security-Policy: default-src 'self'",
                    "Referrer-Policy: strict-origin-when-cross-origin",
                    "Permissions-Policy: accelerometer=(), ...",
                    "X-App-Name: FlaskAPI-Guard-Advanced-Example",
                    "X-Security-Contact: security@example.com",
                ],
                "note": "Check developer tools to see all headers",
            },
        )
    )


@bp.route("/test-page")
def security_headers_test_page():
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">
    <title>Security Headers Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            color: #333;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
        }
        .demo-box {
            background: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .warning { color: #d63384; font-weight: bold; }
        .success { color: #198754; font-weight: bold; }
    </style>
</head>
<body>
    <h1 class="header">FlaskAPI Guard Security Headers Demo</h1>
    <div class="demo-box">
        <h2>Content Security Policy Test</h2>
        <p>This page tests various CSP restrictions:</p>
        <ul>
            <li><strong>Inline Styles:</strong>
                <span id="style-test">Styled</span></li>
            <li><strong>Inline Scripts:</strong>
                <span id="script-test">Waiting...</span></li>
            <li><strong>External Resources:</strong>
                Limited by CSP directives</li>
        </ul>
    </div>
    <div class="demo-box">
        <h2>Security Headers Applied</h2>
        <p>Check the <strong>Network</strong> tab in
        Developer Tools to see all applied headers.</p>
    </div>
    <script>
        var el = document.getElementById('script-test');
        el.textContent = 'Script executed!';
        el.className = 'success';
    </script>
</body>
</html>"""
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


@bp.route("/csp-report", methods=["POST"])
def receive_csp_report():
    data = request.get_json(silent=True) or {}
    csp_report = data.get("csp-report", {})
    logger.warning(
        "CSP Violation: %s blocked %s on %s",
        csp_report.get("violated-directive", "unknown"),
        csp_report.get("blocked-uri", "unknown"),
        csp_report.get("document-uri", "unknown"),
    )
    return jsonify(
        message_response(
            "CSP violation report received",
            details={
                "violated_directive": csp_report.get("violated-directive"),
                "blocked_uri": csp_report.get("blocked-uri"),
                "source_file": csp_report.get("source-file"),
                "line_number": csp_report.get("line-number"),
            },
        )
    )


@bp.route("/frame-test")
def frame_test():
    html = """<!DOCTYPE html>
<html>
<head><title>Frame Options Test</title></head>
<body>
    <h1>X-Frame-Options Test</h1>
    <p>This page has X-Frame-Options: SAMEORIGIN header.</p>
    <p>It can be embedded from same origin, not external sites.</p>
</body>
</html>"""
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


@bp.route("/hsts-info")
def hsts_info():
    return jsonify(
        message_response(
            "HSTS (HTTP Strict Transport Security) is active",
            details={
                "max_age": "31536000 seconds (1 year)",
                "include_subdomains": True,
                "preload": False,
                "description": "Forces HTTPS connections",
                "note": "Enable preload for production",
            },
        )
    )


@bp.route("/security-analysis")
def security_analysis():
    return jsonify(
        message_response(
            "Security analysis of current request",
            details={
                "request_headers": {
                    "user_agent": request.headers.get("user-agent", "Not provided"),
                    "origin": request.headers.get("origin", "Not provided"),
                    "referer": request.headers.get("referer", "Not provided"),
                    "x_forwarded_for": request.headers.get(
                        "x-forwarded-for", "Not provided"
                    ),
                },
                "security_features": [
                    "Content-Type sniffing protection",
                    "Clickjacking protection",
                    "XSS filtering",
                    "HTTPS enforcement",
                    "Content restrictions",
                    "Referrer policy control",
                    "Feature permissions control",
                    "Custom security headers",
                ],
                "recommendations": [
                    "Always use HTTPS in production",
                    "Review and tighten CSP directives",
                    "Monitor CSP violation reports",
                    "Consider HSTS preload for production",
                    "Test security headers with online tools",
                ],
            },
        )
    )
