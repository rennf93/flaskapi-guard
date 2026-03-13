"""Extension supporting modules.

This package contains event bus, metrics, and security check modules
that support the main FlaskAPIGuard class.

The FlaskAPIGuard class itself is defined in flaskapi_guard/extension.py
and should be imported from there:
    from flaskapi_guard.extension import FlaskAPIGuard
"""

from flaskapi_guard.core.events import MetricsCollector, SecurityEventBus

__all__ = ["SecurityEventBus", "MetricsCollector"]
