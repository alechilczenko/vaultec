"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
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
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())

def setup_app_logging():
    """Route Uvicorn, SQLAlchemy, and the root logger through Loguru."""
    logger.remove()

    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
        level="INFO",
        enqueue=True  # keep logging off the request thread
    )

    logging.getLogger("uvicorn").handlers = [InterceptHandler()]
    logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

    logging.getLogger("sqlalchemy.engine").handlers = [InterceptHandler()]

    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
