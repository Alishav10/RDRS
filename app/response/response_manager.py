from app.core.logging_config import (
    get_alert_logger,
    get_audit_logger,
)

from app.response.incident_manager import IncidentManager
from app.response.evidence_manager import EvidenceManager
from app.response.score_manager import ScoreManager
from app.detectors.alert_classifier import AlertClassifier


class ResponseManager:
    """
    Coordinates the defensive response when RDRS
    detects a critical threat.

    Response is copy-only and simulation-safe.
    """

    def __init__(self):
        self.incident_manager = IncidentManager()
        self.evidence_manager = EvidenceManager()
        self.score_manager = ScoreManager()

        self.alert_classifier = AlertClassifier()

        self.alert_logger = get_alert_logger()
        self.audit_logger = get_audit_logger()

    def handle_detection(
        self,
        signal,
        affected_files,
        suspect_process=None,
        event_id=None,
        process_id=None,
    ):
        """
        Handle a DetectionSignal.

        NORMAL and WARNING activity is recorded as a score.

        CRITICAL activity:
        - saves score
        - creates incident
        - logs alert/audit information
        - copies evidence
        """
        classification = self.alert_classifier.classify(signal)

        score_id = self.score_manager.save_score(
            score=signal.threat_score,
            reasons=signal.scoring_reasons,
            event_id=event_id,
            process_id=process_id,
        )

        if signal.threat_level != "CRITICAL":
            return {
                "score_id": score_id,
                "incident_id": None,
                "copied_files": [],
                "classification": classification.classification,
                "title": classification.title,
            }

        incident_id = self.incident_manager.create_incident(
            score=signal.threat_score,
            severity=signal.threat_level,
            reasons=signal.scoring_reasons,
            affected_files=affected_files,
            suspect_process=suspect_process,
            classification=classification,
        )

        copied_files = (
            self.evidence_manager.quarantine_files(
                affected_files=affected_files,
                incident_id=incident_id,
            )
        )

        self.alert_logger.critical(
            f"RANSOMWARE-LIKE ACTIVITY | "
            f"incident_id={incident_id} | "
            f"score={signal.threat_score}/100 | "
            f"affected_files={len(affected_files)} | "
            f"evidence_copied={len(copied_files)}"
        )

        self.audit_logger.info(
            f"RESPONSE_COMPLETED | "
            f"incident_id={incident_id} | "
            f"score_id={score_id} | "
            f"score={signal.threat_score} | "
            f"evidence_copied={len(copied_files)}"
        )

        return {
            "score_id": score_id,
            "incident_id": incident_id,
            "copied_files": copied_files,
            "classification": classification.classification,
            "title": classification.title,
        }