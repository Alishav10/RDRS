from datetime import datetime

import pytest
from sqlalchemy import delete

from app.database.database import SessionLocal
from app.database.models import Incident, Event, Score
from app.response.report_manager import ReportManager


def clean_database(db):
    """
    Remove test data so every test starts with
    a clean database state.
    """
    db.execute(delete(Event))
    db.execute(delete(Score))
    db.execute(delete(Incident))
    db.commit()


def create_test_incident(db):
    incident = Incident(
        title="Possible Ransomware Attack",
        severity="CRITICAL",
        status="OPEN",
        timestamp=datetime.now(),
        description=(
            "RDRS detected suspicious file activity.\n\n"
            "Classification: POSSIBLE_RANSOMWARE\n"
            "Classification Summary: Multiple strong ransomware-like "
            "indicators were detected simultaneously.\n\n"
            "Threat score: 95\n"
            "Suspect process: safe-test-process\n\n"
            "Affected files:\n"
            "- data/sandbox/test1.txt\n"
            "- data/sandbox/test2.txt\n"
        ),
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


def test_get_incident_and_extract_information():
    db = SessionLocal()

    try:
        clean_database(db)

        manager = ReportManager()

        incident = create_test_incident(db)

        result = manager._get_incident(
            db,
            incident.id
        )

        assert result is not None
        assert result.id == incident.id

        assert (
            manager._extract_suspect_process(
                incident.description
            )
            == "safe-test-process"
        )

        assert (
            manager._extract_threat_score(
                incident.description
            )
            == 95.0
        )

        assert manager._extract_affected_files(
            incident.description
        ) == [
            "data/sandbox/test1.txt",
            "data/sandbox/test2.txt",
        ]

    finally:
        db.close()


def test_missing_incident_raises_error():
    manager = ReportManager()

    db = SessionLocal()

    try:
        clean_database(db)

        with pytest.raises(
            ValueError,
            match="Incident 999999 not found"
        ):
            manager._build_report(
                db,
                999999
            )

    finally:
        db.close()


def test_build_report_with_events_and_score():
    db = SessionLocal()

    try:
        clean_database(db)

        manager = ReportManager()

        incident = create_test_incident(db)

        event = Event(
            event_type="MODIFY",
            file_path="data/sandbox/test1.txt",
            timestamp=incident.timestamp,
            extension=".txt",
            old_path=None,
        )

        score = Score(
            timestamp=incident.timestamp,
            score=95,
        )

        db.add(event)
        db.add(score)
        db.commit()

        report = manager._build_report(
            db,
            incident.id
        )

        assert (
            report["report"]["incident_id"]
            == incident.id
        )

        assert (
            report["incident"]["severity"]
            == "CRITICAL"
        )

        assert (
            report["threat_assessment"]["score"]
            == 95.0
        )

        assert (
            report["suspect_process"]
            == "safe-test-process"
        )

        assert len(report["affected_files"]) == 2

        assert len(report["timeline"]) == 1

        assert (
            report["timeline"][0]["event_type"]
            == "MODIFY"
        )

        assert (
            report["timeline"][0]["file_path"]
            == "data/sandbox/test1.txt"
        )

        assert (
            report["timeline"][0]["extension"]
            == ".txt"
        )

        assert (
            report["timeline"][0]["old_path"]
            is None
        )

        assert len(report["recommendations"]) > 0

    finally:
        db.close()


def test_build_report_uses_score_fallback():
    db = SessionLocal()

    try:
        clean_database(db)

        manager = ReportManager()

        incident = Incident(
            title="Test Incident",
            severity="WARNING",
            status="OPEN",
            timestamp=datetime.now(),
            description=(
                "Test incident\n"
                "Suspect process: Unknown\n"
                "Affected files:\n"
                "- data/sandbox/example.txt\n"
            ),
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        score = Score(
            timestamp=incident.timestamp,
            score=55,
        )

        db.add(score)
        db.commit()

        report = manager._build_report(
            db,
            incident.id
        )

        assert (
            report["threat_assessment"]["score"]
            == 55.0
        )

        assert (
            report["suspect_process"]
            == "Unknown"
        )

        assert (
            report["incident"]["severity"]
            == "WARNING"
        )

    finally:
        db.close()


def test_generate_json():
    manager = ReportManager()

    db = SessionLocal()

    try:
        clean_database(db)

        incident = create_test_incident(db)
        incident_id = incident.id

    finally:
        db.close()

    output_file = manager.generate_json(
        incident_id
    )

    try:
        assert output_file.exists()
        assert output_file.suffix == ".json"

        content = output_file.read_text(
            encoding="utf-8"
        )

        assert "RDRS Incident Report" in content
        assert "POSSIBLE_RANSOMWARE" in content
        assert "CRITICAL" in content
        assert "safe-test-process" in content

    finally:
        if output_file.exists():
            output_file.unlink()


def test_generate_csv_with_affected_files():
    manager = ReportManager()

    db = SessionLocal()

    try:
        clean_database(db)

        incident = create_test_incident(db)
        incident_id = incident.id

    finally:
        db.close()

    output_file = manager.generate_csv(
        incident_id
    )

    try:
        assert output_file.exists()
        assert output_file.suffix == ".csv"

        content = output_file.read_text(
            encoding="utf-8"
        )

        assert "Incident ID" in content
        assert "AFFECTED_FILE" in content
        assert "safe-test-process" in content
        assert "test1.txt" in content
        assert "test2.txt" in content

    finally:
        if output_file.exists():
            output_file.unlink()


def test_generate_csv_with_timeline():
    manager = ReportManager()

    db = SessionLocal()

    try:
        clean_database(db)

        incident = create_test_incident(db)

        event = Event(
            event_type="RENAME",
            file_path="data/sandbox/test2.demo",
            timestamp=incident.timestamp,
            extension=".demo",
            old_path="data/sandbox/test2.txt",
        )

        db.add(event)
        db.commit()

        incident_id = incident.id

    finally:
        db.close()

    output_file = manager.generate_csv(
        incident_id
    )

    try:
        assert output_file.exists()
        assert output_file.suffix == ".csv"

        content = output_file.read_text(
            encoding="utf-8"
        )

        assert "RENAME" in content
        assert "test2.demo" in content
        assert "test2.txt" in content
        assert "safe-test-process" in content

    finally:
        if output_file.exists():
            output_file.unlink()


def test_generate_html():
    manager = ReportManager()

    db = SessionLocal()

    try:
        clean_database(db)

        incident = create_test_incident(db)
        incident_id = incident.id

    finally:
        db.close()

    output_file = manager.generate_html(
        incident_id
    )

    try:
        assert output_file.exists()
        assert output_file.suffix == ".html"

        content = output_file.read_text(
            encoding="utf-8"
        )

        assert "RDRS" in content
        assert "Incident" in content
        assert "CRITICAL" in content
        assert "safe-test-process" in content

    finally:
        if output_file.exists():
            output_file.unlink()