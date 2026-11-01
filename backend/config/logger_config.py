"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

import logging
import sys
from loguru import logger

class InterceptHandler(logging.Handler):
    """Send stdlib log records to Loguru."""
    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Skip logging frames so Loguru attributes the real caller.
        frame, depth = logging.currentframe(), 2
        while frame is not None and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.bind(logger_name=record.name).opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )

def _log_format(record):
    if str(record["extra"].get("logger_name", "")).startswith("uvicorn"):
        return "{time:HH:mm:ss} | <level>{level: <8}</level> | {message}\n"
    return "{time:HH:mm:ss} | <level>{level: <8}</level> | {file.name}:{line} | {message}\n"

def _capture(name: str) -> None:
    log = logging.getLogger(name)
    log.handlers = [InterceptHandler()]
    log.propagate = False

def setup_app_logging():
    """One stdout sink. Uvicorn keeps no handler of its own."""
    logger.remove()
    logger.add(
        sys.stdout,
        format=_log_format,
        level="INFO",
        backtrace=True,
        diagnose=False,
    )

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi"):
        _capture(name)
    _capture("sqlalchemy.engine")

    logging.basicConfig(handlers=[InterceptHandler()], level=logging.INFO, force=True)
