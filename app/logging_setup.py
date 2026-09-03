"""
Logging configuration. LOG_FORMAT env var switches between:
  - "text" (default): human-readable, for local development
  - "json": structured, for production log aggregation (ELK,
    CloudWatch, Loki, etc. -- any of these expect one JSON object
    per line, not free-form text)

Both formats include request_id -- the text formatter via a plain
string interpolation, the JSON formatter via log_formatter.py.
"""

import logging
import os

from app.observability.context import get_request_id


class _RequestIdFilter(logging.Filter):
    """Injects request_id into every LogRecord so the text formatter's
    %(request_id)s placeholder resolves -- logging.Filter is the
    standard mechanism for adding extra fields to every record without
    changing every individual logging call."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


def configure_logging(level: int = logging.INFO) -> None:
    log_format = os.environ.get("LOG_FORMAT", "text").lower()
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()  # avoid duplicate handlers on repeated calls (e.g. in tests)

    handler = logging.StreamHandler()
    handler.addFilter(_RequestIdFilter())

    if log_format == "json":
        from app.observability.log_formatter import JSONLogFormatter
        handler.setFormatter(JSONLogFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | req=%(request_id)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

    root_logger.addHandler(handler)

    