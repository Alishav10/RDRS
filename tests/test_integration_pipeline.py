from datetime import datetime

from app.database.database import SessionLocal
from app.database.models import Incident, Alert
from app.detectors.detection_engine import DetectionEngine
from app.detectors.file_monitor import FileEvent
from app.response.response_manager import ResponseManager


def test_full_detection_to_incident_pipeline():
    """
    Integration test for the RDRS detection pipeline.

    Simulates ransomware-like file activity using harmless
    fake FileEvent objects and verifies that the activity
    reaches the response layer and creates a CRITICAL incident.
    """

    db = SessionLocal()

    try:
        # Clean previous test records.
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.commit()

        detection_engine = DetectionEngine()
        response_manager = ResponseManager()

        timestamp = datetime.now()

        # --------------------------------------------------
        # Simulate rapid file modifications
        # --------------------------------------------------

        for i in range(10):
            event = FileEvent(
                event_type="MODIFY",
                file_path=f"data/sandbox/integration_{i}.txt",
                timestamp=timestamp,
                extension=".txt",
                old_path=None,
            )

            signal = detection_engine.add_event(event)

        # --------------------------------------------------
        # Simulate mass renames
        # --------------------------------------------------

        for i in range(3):
            event = FileEvent(
                event_type="RENAME",
                file_path=f"data/sandbox/integration_{i}.demo",
                timestamp=timestamp,
                extension=".demo",
                old_path=f"data/sandbox/integration_{i}.txt",
            )

            signal = detection_engine.add_event(event)

        # --------------------------------------------------
        # Verify detection reached CRITICAL
        # --------------------------------------------------

        assert signal.threat_level == "CRITICAL"
        assert signal.threat_score >= 70

        # --------------------------------------------------
        # Verify ransomware-like indicators
        # --------------------------------------------------

        assert signal.rapid_encryption is True
        assert signal.mass_rename is True

        # --------------------------------------------------
        # Send detection to response pipeline
        # --------------------------------------------------

        affected_files = detection_engine.get_affected_files()

        response_result = response_manager.handle_detection(
            signal=signal,
            affected_files=affected_files,
            suspect_process="integration-test-process",
        )

        # --------------------------------------------------
        # Verify incident was created
        # --------------------------------------------------

        assert response_result["incident_id"] is not None

        assert (
            response_result["classification"]
            == "RANSOMWARE_LIKE_FILE_ACTIVITY"
        )

        # --------------------------------------------------
        # Verify database incident
        # --------------------------------------------------

        incident = (
            db.query(Incident)
            .filter(
                Incident.id
                == response_result["incident_id"]
            )
            .first()
        )

        assert incident is not None
        assert incident.severity == "CRITICAL"

        assert (
            incident.title
            == "Ransomware-Like File Activity"
        )

        assert (
            "RANSOMWARE_LIKE_FILE_ACTIVITY"
            in incident.description
        )

        assert (
            "integration-test-process"
            in incident.description
        )

        # --------------------------------------------------
        # Verify alert was created
        # --------------------------------------------------

        alerts = (
            db.query(Alert)
            .order_by(Alert.id.desc())
            .all()
        )

        assert len(alerts) > 0

        alert = alerts[0]

        assert (
            "RANSOMWARE_LIKE_FILE_ACTIVITY"
            in alert.message
        )

        assert (
            "Ransomware-Like File Activity"
            in alert.message
        )

        assert (
            "integration-test-process"
            in alert.message
        )

    finally:
        db.close()