import logging
from datetime import datetime, timezone
from typing import Any

from flask import Request

from flaskapi_guard.models import SecurityConfig


class MetricsCollector:
    """Centralized metrics collection for extension."""

    def __init__(self, agent_handler: Any, config: SecurityConfig):
        """
        Initialize the MetricsCollector.

        Args:
            agent_handler: The agent handler instance for sending metrics
            config: Security configuration
        """
        self.agent_handler = agent_handler
        self.config = config
        self.logger = logging.getLogger(__name__)

    def send_metric(
        self, metric_type: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """
        Send performance metric to agent.

        Args:
            metric_type: Type of metric (e.g., "response_time", "request_count")
            value: Metric value
            tags: Optional tags/labels for the metric
        """
        if self.agent_handler and self.config.agent_enable_metrics:
            try:
                from guard_agent import SecurityMetric

                metric = SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type=metric_type,
                    value=value,
                    tags=tags or {},
                )
                self.agent_handler.send_metric(metric)
            except Exception as e:
                self.logger.error(f"Failed to send metric to agent: {e}")

    def collect_request_metrics(
        self, request: Request, response_time: float, status_code: int
    ) -> None:
        """
        Collect request metrics for agent.

        Args:
            request: The incoming request
            response_time: Time taken to process the request
            status_code: HTTP status code of the response
        """
        if not self.agent_handler or not self.config.agent_enable_metrics:
            return

        endpoint = request.path
        method = request.method

        self.send_metric(
            "response_time",
            response_time,
            {"endpoint": endpoint, "method": method, "status": str(status_code)},
        )

        self.send_metric("request_count", 1.0, {"endpoint": endpoint, "method": method})

        if status_code >= 400:
            self.send_metric(
                "error_rate",
                1.0,
                {"endpoint": endpoint, "method": method, "status": str(status_code)},
            )
