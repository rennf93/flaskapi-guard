# flaskapi_guard/core/validation/context.py
from dataclasses import dataclass
from logging import Logger

from flaskapi_guard.core.events import SecurityEventBus
from flaskapi_guard.models import SecurityConfig


@dataclass
class ValidationContext:
    """Context for request validation operations."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
