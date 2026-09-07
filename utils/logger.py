"""Application logging for diagnostics without exposing errors in the GUI."""

import logging
from pathlib import Path


def get_logger(name: str = "apk_threat_analyzer") -> logging.Logger:
    """Return the shared file logger, creating it only once."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    project_root = Path(__file__).resolve().parents[1]
    log_folder = project_root / "logs"
    log_folder.mkdir(exist_ok=True)
    handler = logging.FileHandler(log_folder / "application.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger
