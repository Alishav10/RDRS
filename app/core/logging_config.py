from pathlib import Path

from loguru import logger

from app.core.config import config


def setup_logging():
    """
    Configure RDRS logging.

    Creates separate rotating log files for:
    - system
    - events
    - alerts
    - errors
    - audit
    """

    log_config = config["logging"]

    log_directory = Path(log_config["directory"])
    log_directory.mkdir(parents=True, exist_ok=True)

    # Remove Loguru's default handler
    logger.remove()

    rotation = log_config.get("rotation", "10 MB")
    retention = log_config.get("retention", "7 days")
    level = log_config.get("level", "INFO")

    # Console logging
    logger.add(
        sink=lambda message: print(message, end=""),
        level=level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    )

    # System log
    logger.add(
        log_directory / "system.log",
        rotation=rotation,
        retention=retention,
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    )

    # File events
    logger.add(
        log_directory / "events.log",
        rotation=rotation,
        retention=retention,
        level="INFO",
        filter=lambda record: record["extra"].get("log_type") == "event",
        format="{time:YYYY-MM-DD HH:mm:ss} | EVENT | {message}",
    )

    # Alerts
    logger.add(
        log_directory / "alerts.log",
        rotation=rotation,
        retention=retention,
        level="WARNING",
        filter=lambda record: record["extra"].get("log_type") == "alert",
        format="{time:YYYY-MM-DD HH:mm:ss} | ALERT | {level} | {message}",
    )

    # Errors
    logger.add(
        log_directory / "errors.log",
        rotation=rotation,
        retention=retention,
        level="ERROR",
        filter=lambda record: record["extra"].get("log_type") == "error",
        format="{time:YYYY-MM-DD HH:mm:ss} | ERROR | {message}",
    )

    # Audit
    logger.add(
        log_directory / "audit.log",
        rotation=rotation,
        retention=retention,
        level="INFO",
        filter=lambda record: record["extra"].get("log_type") == "audit",
        format="{time:YYYY-MM-DD HH:mm:ss} | AUDIT | {message}",
    )


def get_event_logger():
    return logger.bind(log_type="event")


def get_alert_logger():
    return logger.bind(log_type="alert")


def get_error_logger():
    return logger.bind(log_type="error")


def get_audit_logger():
    return logger.bind(log_type="audit")