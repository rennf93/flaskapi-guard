"""Extension events package.

This package provides event bus and metrics collection for the extension.
"""

from flaskapi_guard.core.events.extension_events import SecurityEventBus
from flaskapi_guard.core.events.metrics import MetricsCollector

__all__ = ["SecurityEventBus", "MetricsCollector"]
