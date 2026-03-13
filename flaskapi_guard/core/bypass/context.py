# flaskapi_guard/core/bypass/context.py
from dataclasses import dataclass
from logging import Logger

from flaskapi_guard.core.events import SecurityEventBus
from flaskapi_guard.core.responses import ErrorResponseFactory
from flaskapi_guard.core.routing import RouteConfigResolver
from flaskapi_guard.core.validation import RequestValidator
from flaskapi_guard.models import SecurityConfig


@dataclass
class BypassContext:
    """Context for bypass handler operations."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    route_resolver: RouteConfigResolver
    response_factory: ErrorResponseFactory
    validator: RequestValidator
