from flask import Blueprint, jsonify, request

from app.models import message_response

bp = Blueprint("test", __name__, url_prefix="/test")


@bp.route("/xss-test", methods=["POST"])
def test_xss_detection():
    data = request.get_json(silent=True) or {}
    payload = data if isinstance(data, str) else data.get("payload", "")
    return jsonify(
        message_response(
            "XSS test payload processed",
            details={"payload": payload, "detected": False},
        )
    )


@bp.route("/sql-injection")
def test_sql_injection():
    query = request.args.get("query", "")
    return jsonify(
        message_response(
            "SQL injection test processed",
            details={"query": query, "detected": False},
        )
    )


@bp.route("/path-traversal/<path:file_path>")
def test_path_traversal(file_path: str):
    return jsonify(
        message_response(
            "Path traversal test",
            details={"path": file_path, "detected": False},
        )
    )


@bp.route("/command-injection", methods=["POST"])
def test_command_injection():
    data = request.get_json(silent=True) or {}
    command = data if isinstance(data, str) else data.get("command", "")
    return jsonify(
        message_response(
            "Command injection test processed",
            details={"command": command, "detected": False},
        )
    )


@bp.route("/mixed-attack", methods=["POST"])
def test_mixed_attack():
    data = request.get_json(silent=True) or {}
    return jsonify(
        message_response(
            "Mixed attack test processed",
            details={
                "xss_test": data.get("input"),
                "sql_test": data.get("query"),
                "path_test": data.get("path"),
                "cmd_test": data.get("cmd"),
                "honeypot": data.get("honeypot_field"),
            },
        )
    )
