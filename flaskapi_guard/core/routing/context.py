# flaskapi_guard/core/routing/context.py
from dataclasses import dataclass
from logging import Logger

from flaskapi_guard.decorators.base import BaseSecurityDecorator
from flaskapi_guard.models import SecurityConfig


@dataclass
class RoutingContext:
    """
    Context for routing and decorator configuration resolution.

    Provides minimal dependencies needed for route matching and
    configuration resolution through clean dependency injection pattern.
    """

    config: SecurityConfig
    logger: Logger

    # Optional dependencies
    guard_decorator: BaseSecurityDecorator | None = None
