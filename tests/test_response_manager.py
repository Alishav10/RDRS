from pathlib import Path

from app.detectors.detection_engine import DetectionSignal
from app.response.response_manager import ResponseManager
from app.database.database import SessionLocal
from app.database.models import Incident, Alert

def test_critical_detection_triggers_response(tmp_path):
    evidence_file = (
        tmp_path / "safe_evidence.txt"
    )

    original_content = (
        "Safe RDRS response integration test"
    )

    evidence_file.write_text(
        original_content,
        encoding="utf-8",
    )

    signal = DetectionSignal(
        files_modified=10,
        renames=3,
        extension_changes=3,
        average_entropy=7.8,
        window_seconds=60,
        dangerous_burst=True,
        rapid_encryption=True,
        mass_rename=True,
        high_entropy=True,
        threat_score=95,
        threat_level="CRITICAL",
        scoring_reasons=[
            "Rapid encryption/modification activity (+40)",
            "Mass file rename activity (+30)",
            "High file entropy (+25)",
        ],
        reasons=[
            "High file modification rate",
            "Mass file rename activity",
            "High average file entropy",
        ],
    )

    manager = ResponseManager()

    result = manager.handle_detection(
        signal=signal,
        affected_files=[str(evidence_file)],
        suspect_process="safe-test-process",
    )

    assert result["score_id"] is not None
    assert result["incident_id"] is not None
    assert len(result["copied_files"]) == 1

    copied_file = Path(
        result["copied_files"][0]
    )

    assert copied_file.exists()

    # Original must remain untouched.
    assert evidence_file.exists()

    assert (
        evidence_file.read_text(
            encoding="utf-8"
        )
        == original_content
    )
def test_critical_incident_contains_classification(tmp_path):
        evidence_file = tmp_path / "classification_test.txt"

        evidence_file.write_text(
            "Safe classification integration test",
            encoding="utf-8",
        )

        signal = DetectionSignal(
            files_modified=10,
            renames=3,
            extension_changes=3,
            average_entropy=7.8,
            window_seconds=60,
            dangerous_burst=True,
            rapid_encryption=True,
            mass_rename=True,
            high_entropy=True,
            threat_score=95,
            threat_level="CRITICAL",
            scoring_reasons=[
                "Rapid encryption/modification activity (+40)",
                "Mass file rename activity (+30)",
                "High file entropy (+25)",
            ],
            reasons=[
                "High file modification rate",
                "Mass file rename activity",
                "High average file entropy",
            ],
        )

        manager = ResponseManager()

        result = manager.handle_detection(
            signal=signal,
            affected_files=[str(evidence_file)],
            suspect_process="safe-classification-process",
        )

        incident_id = result["incident_id"]

        db = SessionLocal()

        try:
            incident = db.query(Incident).filter(
                Incident.id == incident_id
            ).first()

            assert incident is not None

            assert incident.title == "Possible Ransomware Attack"

            assert "Classification: POSSIBLE_RANSOMWARE" in (
                incident.description
            )

            alert = db.query(Alert).order_by(
                Alert.id.desc()
            ).first()

            assert alert is not None

            assert "POSSIBLE_RANSOMWARE" in alert.message
            assert "Possible Ransomware Attack" in alert.message

        finally:
            db.close()