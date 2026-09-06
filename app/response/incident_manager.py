from pathlib import Path
from datetime import datetime

from app.core.config import config
from app.core.logging_config import (
    get_alert_logger,
    get_audit_logger,
)
from app.database.database import SessionLocal
from app.database.models import Incident


class IncidentManager:
    """
    Handles incident creation and evidence preservation.

    Response is defensive and copy-only.
    Original evidence files are never modified or deleted.
    """

    def __init__(self):

        self.alert_logger = get_alert_logger()
        self.audit_logger = get_audit_logger()

        response_config = config["response"]

        self.simulation_mode = response_config[
            "simulation_mode"
        ]

        self.quarantine_directory = Path(
            response_config[
                "quarantine_directory"
            ]
        )

        self.quarantine_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def create_incident(
        self,
        score,
        severity,
        reasons,
        affected_files,
        suspect_process=None,
    ):
        """
        Create a security incident in the database.
        """

        description = (
            "RDRS detected suspicious ransomware-like "
            "file activity.\n\n"
            f"Threat score: {score}\n"
            f"Severity: {severity}\n"
            f"Suspect process: "
            f"{suspect_process or 'Unknown'}\n\n"
            "Reasons:\n"
            + "\n".join(
                f"- {reason}"
                for reason in reasons
            )
            + "\n\n"
            "Affected files:\n"
            + "\n".join(
                f"- {file_path}"
                for file_path in affected_files
            )
        )

        db = SessionLocal()

        try:

            incident = Incident(
                title=(
                    "Possible Ransomware Activity"
                ),
                description=description,
                severity=severity,
                status="OPEN",
                timestamp=datetime.now(),
            )

            db.add(incident)

            db.commit()

            db.refresh(incident)

            incident_id = incident.id

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

        # ----------------------------------------
        # ALERT LOG
        # ----------------------------------------

        self.alert_logger.warning(
            f"CRITICAL INCIDENT CREATED | "
            f"incident_id={incident_id} | "
            f"score={score} | "
            f"severity={severity} | "
            f"suspect_process="
            f"{suspect_process or 'Unknown'}"
        )

        # ----------------------------------------
        # AUDIT LOG
        # ----------------------------------------

        self.audit_logger.info(
            f"INCIDENT_CREATED | "
            f"incident_id={incident_id} | "
            f"score={score} | "
            f"severity={severity} | "
            f"affected_files="
            f"{len(affected_files)} | "
            f"suspect_process="
            f"{suspect_process or 'Unknown'}"
        )

        return incident_id