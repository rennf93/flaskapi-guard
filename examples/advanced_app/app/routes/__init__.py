from app.routes.access_control import bp as access_bp
from app.routes.admin import bp as admin_bp
from app.routes.advanced import bp as advanced_bp
from app.routes.auth import bp as auth_bp
from app.routes.basic import bp as basic_bp
from app.routes.behavioral import bp as behavior_bp
from app.routes.content import bp as content_bp
from app.routes.headers import bp as headers_bp
from app.routes.health import bp as health_bp
from app.routes.rate_limiting import bp as rate_bp
from app.routes.testing import bp as test_bp

__all__ = [
    "access_bp",
    "admin_bp",
    "advanced_bp",
    "auth_bp",
    "basic_bp",
    "behavior_bp",
    "content_bp",
    "headers_bp",
    "health_bp",
    "rate_bp",
    "test_bp",
]
