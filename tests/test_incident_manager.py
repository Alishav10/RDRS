from app.database.database import SessionLocal
from app.database.models import Incident
from app.response.incident_manager import IncidentManager


def test_critical_incident_is_created():

    manager = IncidentManager()

    affected_files = [
        "data/sandbox/test1.txt",
        "data/sandbox/test2.txt",
    ]

    incident_id = manager.create_incident(
        score=95,
        severity="CRITICAL",
        reasons=[
            "High file modification rate",
            "Multiple extension changes",
            "High file entropy",
        ],
        affected_files=affected_files,
        suspect_process="python.exe",
    )

    assert incident_id is not None

    db = SessionLocal()

    try:

        incident = db.query(
            Incident
        ).filter(
            Incident.id == incident_id
        ).first()

        assert incident is not None

        assert incident.severity == "CRITICAL"

        assert (
            "python.exe"
            in incident.description
        )

        assert (
            "data/sandbox/test1.txt"
            in incident.description
        )

    finally:

        db.close()