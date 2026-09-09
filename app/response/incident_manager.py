
from pathlib import Path
from datetime import datetime

from app.core.config import config
from app.core.logging_config import (
    get_alert_logger,
    get_audit_logger,
)
from app.database.database import SessionLocal
from app.database.models import Incident, Alert


class IncidentManager:
    """
    Handles incident creation and alert generation.

    Response is defensive and copy-only.
    Original evidence files are never modified or deleted.
    """

    def __init__(self):
        self.alert_logger = get_alert_logger()
        self.audit_logger = get_audit_logger()

        response_config = config["response"]

        self.simulation_mode = response_config["simulation_mode"]

        self.quarantine_directory = Path(
            response_config["quarantine_directory"]
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
        classification=None,
    ):
        description = (
            "RDRS detected suspicious ransomware-like "
            f"Classification: "
            f"{classification.classification if classification else 'UNKNOWN'}\n"
            f"Classification Summary: "
            f"{classification.summary if classification else 'No classification available.'}\n\n"
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
            # -------------------------------------------------
            # 1. Create incident
            # -------------------------------------------------

            incident = Incident(
                title=(
                    classification.title
                    if classification
                    else "Possible Ransomware Activity"
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

            # -------------------------------------------------
            # 2. Create alert database record
            # -------------------------------------------------

            alert = Alert(
                severity=severity,
                message=(
                    f"{classification.title if classification else 'Suspicious Activity'} "
                    f"| Classification: "
                    f"{classification.classification if classification else 'UNKNOWN'} "
                    f"| Incident ID: {incident_id}. "
                    f"Threat score: {score}/100. "
                    f"Suspect process: "
                    f"{suspect_process or 'Unknown'}"
                ),
                timestamp=datetime.now(),
            )

            db.add(alert)
            db.commit()
            db.refresh(alert)

            alert_id = alert.id

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

        # -----------------------------------------------------
        # 3. Write alert log
        # -----------------------------------------------------

        self.alert_logger.warning(
            f"CRITICAL INCIDENT CREATED | "
            f"incident_id={incident_id} | "
            f"alert_id={alert_id} | "
            f"score={score} | "
            f"severity={severity} | "
            f"suspect_process="
            f"{suspect_process or 'Unknown'}"
        )

        # -----------------------------------------------------
        # 4. Write audit log
        # -----------------------------------------------------

        self.audit_logger.info(
            f"INCIDENT_CREATED | "
            f"incident_id={incident_id} | "
            f"alert_id={alert_id} | "
            f"score={score} | "
            f"severity={severity} | "
            f"affected_files={len(affected_files)} | "
            f"suspect_process="
            f"{suspect_process or 'Unknown'}"
        )

        return incident_id

