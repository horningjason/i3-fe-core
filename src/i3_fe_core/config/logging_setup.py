"""Structured stdlib logging configuration for i3-fe-core.

Call configure_logging() once at startup.  It attaches a single handler to
"i3_fe_core" and optionally to one FE-supplied logger name, preventing
double-logging by setting propagate=False on both.
"""

from __future__ import annotations

import logging
import sys


_FORMATTER = logging.Formatter(
    fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


def _attach_handler(logger: logging.Logger, level: int) -> None:
    """Add a stdout StreamHandler if none is present; set level; stop propagation."""
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_FORMATTER)
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def configure_logging(
    level: str = "INFO",
    fe_logger_name: str | None = None,
) -> None:
    """Configure structured logging for i3_fe_core (and optionally an FE logger).

    Args:
        level: stdlib log-level name — DEBUG / INFO / WARNING / ERROR / CRITICAL.
        fe_logger_name: optional name of the FE's root logger to configure
            at the same level using the same handler.
    """
    numeric = logging.getLevelName(level.upper())
    if not isinstance(numeric, int):
        raise ValueError(f"Unknown log level: {level!r}")

    _attach_handler(logging.getLogger("i3_fe_core"), numeric)

    if fe_logger_name:
        _attach_handler(logging.getLogger(fe_logger_name), numeric)
