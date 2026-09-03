# app/observability/log_formatter.py
"""
A JSON log formatter that automatically includes the current
request_id/company_id from context.py in EVERY log line, without any
individual logging call needing to pass them explicitly. This is
what makes correlation actually usable: grep or query for one
request_id and get every log line touched by that request, across
every module, without having to remember to add it manually at each
call site.
"""

import json
import logging

from app.observability.context import get_company_id, get_request_id


class JSONLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
            "company_id": get_company_id(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)
        
        