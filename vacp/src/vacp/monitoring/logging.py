"""
Structured Logging for Koba

Provides JSON-formatted logging for production use.
"""

import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False


class JSONFormatter(logging.Formatter):
    """JSON log formatter for standard logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "lineno", "funcName", "created",
                "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "exc_info", "exc_text", "stack_info",
                "message"
            ):
                log_data[key] = value

        return json.dumps(log_data)


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    log_file: Optional[str] = None,
) -> None:
    """
    Configure logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON formatting (recommended for production)
        log_file: Optional file path for log output
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )

    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # Configure structlog if available
    if STRUCTLOG_AVAILABLE:
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer() if json_format else structlog.dev.ConsoleRenderer(),
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> Any:
    """
    Get a logger instance.

    Returns structlog logger if available, else standard logger.
    """
    if STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    return logging.getLogger(name)


class RequestLogger:
    """Context manager for logging request details."""

    def __init__(
        self,
        logger: Any,
        method: str,
        path: str,
        request_id: Optional[str] = None,
    ):
        self.logger = logger
        self.method = method
        self.path = path
        self.request_id = request_id
        self.start_time = None

    def __enter__(self):
        import time
        self.start_time = time.time()
        self.logger.info(
            "request_started",
            method=self.method,
            path=self.path,
            request_id=self.request_id,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        duration_ms = (time.time() - self.start_time) * 1000

        if exc_type:
            self.logger.error(
                "request_failed",
                method=self.method,
                path=self.path,
                request_id=self.request_id,
                duration_ms=duration_ms,
                error=str(exc_val),
            )
        else:
            self.logger.info(
                "request_completed",
                method=self.method,
                path=self.path,
                request_id=self.request_id,
                duration_ms=duration_ms,
            )

        return False


class AuditLogger:
    """Specialized logger for audit events."""

    def __init__(self, name: str = "koba.audit"):
        self.logger = get_logger(name)

    def log_tool_execution(
        self,
        tool_id: str,
        agent_id: str,
        tenant_id: str,
        decision: str,
        receipt_id: Optional[str] = None,
        **kwargs
    ) -> None:
        """Log a tool execution event."""
        self.logger.info(
            "tool_executed",
            event_type="tool_execution",
            tool_id=tool_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            decision=decision,
            receipt_id=receipt_id,
            **kwargs
        )

    def log_policy_decision(
        self,
        tool_id: str,
        decision: str,
        bundle_id: str,
        rule_id: Optional[str] = None,
        **kwargs
    ) -> None:
        """Log a policy decision."""
        self.logger.info(
            "policy_decision",
            event_type="policy",
            tool_id=tool_id,
            decision=decision,
            bundle_id=bundle_id,
            rule_id=rule_id,
            **kwargs
        )

    def log_auth_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        success: bool = True,
        **kwargs
    ) -> None:
        """Log an authentication event."""
        level = "info" if success else "warning"
        getattr(self.logger, level)(
            "auth_event",
            event_type=event_type,
            user_id=user_id,
            tenant_id=tenant_id,
            success=success,
            **kwargs
        )

    def log_containment_event(
        self,
        event_type: str,
        severity: str = "info",
        **kwargs
    ) -> None:
        """Log a containment system event."""
        level = severity if severity in ("info", "warning", "error", "critical") else "info"
        getattr(self.logger, level)(
            "containment_event",
            event_type=event_type,
            severity=severity,
            **kwargs
        )

    def log_blockchain_anchor(
        self,
        anchor_id: str,
        tree_size: int,
        transaction_id: str,
        blockchain: str = "hedera",
        **kwargs
    ) -> None:
        """Log a blockchain anchor event."""
        self.logger.info(
            "blockchain_anchor",
            event_type="anchor",
            anchor_id=anchor_id,
            tree_size=tree_size,
            transaction_id=transaction_id,
            blockchain=blockchain,
            **kwargs
        )
