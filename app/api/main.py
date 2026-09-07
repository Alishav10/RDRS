
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.core.config import config
from app.core.entropy import calculate_file_entropy
from app.database.database import SessionLocal
from app.database.models import Alert, Event, Incident, ProcessSnapshot, Score


app = FastAPI(
    title="RDRS REST API",
    description="REST API for the Ransomware Detection and Response System",
    version="1.0.0",
)


# ---------------------------------------------------------
# Settings request model
# ---------------------------------------------------------

class SettingsRequest(BaseModel):
    entropy_threshold: float = Field(
        default=7.0,
        ge=0.0,
        le=8.0,
    )

    rapid_change_threshold: int = Field(
        default=10,
        ge=1,
    )

    rename_threshold: int = Field(
        default=3,
        ge=1,
    )


# ---------------------------------------------------------
# GET /health
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "RDRS REST API",
        "timestamp": datetime.now().isoformat(),
    }


# ---------------------------------------------------------
# GET /status
# ---------------------------------------------------------

@app.get("/status")
def status():
    db = SessionLocal()

    try:
        event_count = db.query(Event).count()
        process_count = db.query(ProcessSnapshot).count()
        alert_count = db.query(Alert).count()
        incident_count = db.query(Incident).count()
        score_count = db.query(Score).count()

        return {
            "system": "RDRS",
            "status": "running",
            "version": config["app"]["version"],
            "statistics": {
                "events": event_count,
                "process_snapshots": process_count,
                "alerts": alert_count,
                "incidents": incident_count,
                "scores": score_count,
            },
            "timestamp": datetime.now().isoformat(),
        }

    finally:
        db.close()


# ---------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------

@app.get("/alerts")
def alerts():
    db = SessionLocal()

    try:
        records = (
            db.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(50)
            .all()
        )

        return {
            "count": len(records),
            "alerts": [
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat(),
                }
                for alert in records
            ],
        }

    finally:
        db.close()


# ---------------------------------------------------------
# GET /events
# ---------------------------------------------------------

@app.get("/events")
def events():
    db = SessionLocal()

    try:
        records = (
            db.query(Event)
            .order_by(Event.timestamp.desc())
            .limit(100)
            .all()
        )

        return {
            "count": len(records),
            "events": [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "file_path": event.file_path,
                    "extension": event.extension,
                    "old_path": event.old_path,
                    "timestamp": event.timestamp.isoformat(),
                }
                for event in records
            ],
        }

    finally:
        db.close()


# ---------------------------------------------------------
# GET /reports
# ---------------------------------------------------------

@app.get("/reports")
def reports():
    db = SessionLocal()

    try:
        incidents = (
            db.query(Incident)
            .order_by(Incident.timestamp.desc())
            .limit(50)
            .all()
        )

        scores = (
            db.query(Score)
            .order_by(Score.timestamp.desc())
            .limit(50)
            .all()
        )

        return {
            "incidents": [
                {
                    "id": incident.id,
                    "title": incident.title,
                    "description": incident.description,
                    "severity": incident.severity,
                    "status": incident.status,
                    "timestamp": incident.timestamp.isoformat(),
                }
                for incident in incidents
            ],
            "scores": [
                {
                    "id": score.id,
                    "score": score.score,
                    "reason": score.reason,
                    "event_id": score.event_id,
                    "process_id": score.process_id,
                    "timestamp": score.timestamp.isoformat(),
                }
                for score in scores
            ],
        }

    finally:
        db.close()


# ---------------------------------------------------------
# POST /scan
# ---------------------------------------------------------

@app.post("/scan")
def scan():
    sandbox_directory = Path("data/sandbox")

    if not sandbox_directory.exists():
        return {
            "status": "completed",
            "files_scanned": 0,
            "suspicious_files": [],
            "message": "Sandbox directory does not exist.",
            "timestamp": datetime.now().isoformat(),
        }

    entropy_config = config["monitoring"]["entropy"]

    sample_size = entropy_config["sample_size"]
    suspicious_threshold = entropy_config["suspicious_threshold"]

    files_scanned = 0
    suspicious_files = []

    for file_path in sandbox_directory.rglob("*"):

        if not file_path.is_file():
            continue

        files_scanned += 1

        try:
            entropy = calculate_file_entropy(
                file_path,
                sample_size=sample_size,
            )

            if entropy >= suspicious_threshold:
                suspicious_files.append(
                    {
                        "file": str(file_path),
                        "entropy": round(entropy, 4),
                        "reason": "High file entropy",
                    }
                )

        except (OSError, PermissionError):
            continue

    return {
        "status": "completed",
        "files_scanned": files_scanned,
        "suspicious_files": suspicious_files,
        "suspicious_count": len(suspicious_files),
        "mode": "safe_read_only",
        "timestamp": datetime.now().isoformat(),
    }


# ---------------------------------------------------------
# POST /settings
# ---------------------------------------------------------

@app.post("/settings")
def update_settings(settings: SettingsRequest):

    return {
        "status": "accepted",
        "message": "Settings validated successfully.",
        "settings": {
            "entropy_threshold": settings.entropy_threshold,
            "rapid_change_threshold": settings.rapid_change_threshold,
            "rename_threshold": settings.rename_threshold,
        },
        "note": (
            "Settings are validated by the API. "
            "Persistent configuration changes are not performed yet."
        ),
        "timestamp": datetime.now().isoformat(),
    }

