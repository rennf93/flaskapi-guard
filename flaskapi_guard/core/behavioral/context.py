from dataclasses import dataclass
from logging import Logger

from flaskapi_guard.core.events import SecurityEventBus
from flaskapi_guard.decorators.base import BaseSecurityDecorator
from flaskapi_guard.models import SecurityConfig


@dataclass
class BehavioralContext:
    """Context for behavioral rule processing."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
