from pathlib import Path

from app.detectors.detection_engine import DetectionSignal
from app.response.response_manager import ResponseManager


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