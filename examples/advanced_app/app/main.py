import logging
from typing import Any

from flask import Flask, jsonify

from app.models import error_response
from app.routes import (
    access_bp,
    admin_bp,
    advanced_bp,
    auth_bp,
    basic_bp,
    behavior_bp,
    content_bp,
    headers_bp,
    health_bp,
    rate_bp,
    test_bp,
)
from app.security import guard, security_config
from flaskapi_guard import FlaskAPIGuard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
flask_guard = FlaskAPIGuard(app, config=security_config)
flask_guard.set_decorator_handler(guard)

app.register_blueprint(health_bp)
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


@app.route("/")
def root() -> tuple[Any, int]:
    return jsonify(
        {
            "message": "FlaskAPI Guard Advanced Example API",
            "version": "1.0.0",
            "infrastructure": {
                "reverse_proxy": "nginx",
                "process_manager": "gunicorn",
                "cache": "redis",
            },
            "routes": {
                "/health": "Health checks",
                "/basic": "Basic security features",
                "/access": "Access control",
                "/auth": "Authentication examples",
                "/rate": "Rate limiting",
                "/behavior": "Behavioral analysis",
                "/headers": "Security headers",
                "/content": "Content filtering",
                "/advanced": "Advanced features",
                "/admin": "Admin utilities",
                "/test": "Security testing",
            },
        }
    ), 200


@app.errorhandler(404)
def not_found(e: Exception) -> tuple[Any, int]:
    return jsonify(error_response("Not found", "HTTP_404")), 404


@app.errorhandler(500)
def internal_error(e: Exception) -> tuple[Any, int]:
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    return jsonify(error_response("Internal server error", "INTERNAL_ERROR")), 500


logger.info("FlaskAPI Guard Advanced Example starting up...")
logger.info("Security features enabled:")
logger.info(f"  - Rate limiting: {security_config.enable_rate_limiting}")
logger.info(f"  - IP banning: {security_config.enable_ip_banning}")
logger.info(
    f"  - Penetration detection: {security_config.enable_penetration_detection}"
)
logger.info(f"  - Redis: {security_config.enable_redis}")
