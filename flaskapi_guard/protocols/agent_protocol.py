from typing import Any, Protocol, runtime_checkable

from flaskapi_guard.protocols.redis_protocol import RedisHandlerProtocol


@runtime_checkable
class AgentHandlerProtocol(Protocol):
    """
    Protocol for Flask API Guard Agent handlers.

    This protocol defines the interface that agent handlers must implement
    to integrate with Flask API Guard's security system.
    """

    def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        """
        Initialize Redis connection for the agent.

        Args:
            redis_handler: The Redis handler instance to use for persistence
        """
        # ...

    def send_event(self, event: Any) -> None:
        """
        Send a security event to the agent.

        Args:
            event: SecurityEvent instance containing event data
        """
        # ...

    def send_metric(self, metric: Any) -> None:
        """
        Send a performance metric to the agent.

        Args:
            metric: SecurityMetric instance containing metric data
        """
        # ...

    def start(self) -> None:
        """
        Start the agent background tasks and connections.
        """
        # ...

    def stop(self) -> None:
        """
        Stop the agent and cleanup resources.
        """
        # ...

    def flush_buffer(self) -> None:
        """
        Force flush any buffered events to the remote endpoint.
        """
        # ...

    def get_dynamic_rules(self) -> Any | None:
        """
        Fetch dynamic rules from the SaaS platform.

        Returns:
            DynamicRules instance if available, None otherwise
        """
        # ...

    def health_check(self) -> bool:
        """
        Check if the agent is healthy and connected.

        Returns:
            True if agent is healthy, False otherwise
        """
        # ...
