from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core.config import config
from app.core.entropy import calculate_file_entropy
from app.database.database import SessionLocal
from app.database.models import Alert, Event, Incident, ProcessSnapshot, Score
from app.response.report_manager import ReportManager
from fastapi import HTTPException


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

@app.get("/dashboard")
def dashboard():
    dashboard_file = (
        Path(__file__).resolve().parent.parent
        / "dashboard"
        / "index.html"
    )

    return FileResponse(dashboard_file)

@app.get("/dashboard/data")
def dashboard_data():
    """
    Return live telemetry for the security operations dashboard.

    The threat state is based on activity observed during the
    most recent 60-second window rather than the last historical score.
    """

    db = SessionLocal()

    try:
        now = datetime.now()
        window_start = now - timedelta(seconds=60)

        # ---------------------------------------------------------
        # 1. CURRENT FILE ACTIVITY
        # ---------------------------------------------------------

        recent_events = (
            db.query(Event)
            .filter(Event.timestamp >= window_start)
            .order_by(Event.timestamp.asc())
            .all()
        )

        modifications = [
            event for event in recent_events
            if event.event_type == "MODIFY"
        ]

        renames = [
            event for event in recent_events
            if event.event_type == "RENAME"
        ]

        creates = [
            event for event in recent_events
            if event.event_type == "CREATE"
        ]

        deletes = [
            event for event in recent_events
            if event.event_type == "DELETE"
        ]

        # ---------------------------------------------------------
        # 2. CALCULATE CURRENT THREAT SIGNALS
        # ---------------------------------------------------------

        modification_count = len(modifications)
        rename_count = len(renames)

        suspicious_extension_count = sum(
            1
            for event in recent_events
            if event.extension.lower() in {
                ".locked",
                ".encrypted",
                ".crypt",
                ".enc",
                ".ryk",
                ".wncry",
            }
        )

        # Recent file entropy
        entropy_values = []

        for event in recent_events[-30:]:
            try:
                file_path = Path(event.file_path)

                if file_path.exists() and file_path.is_file():
                    entropy_values.append(
                        calculate_file_entropy(file_path)
                    )
            except Exception:
                continue

        average_entropy = (
            sum(entropy_values) / len(entropy_values)
            if entropy_values
            else 0.0
        )
        # ---------------------------------------------------------
        # 3. CPU SPIKE DETECTION — CURRENT 60-SECOND WINDOW
        # ---------------------------------------------------------

        cpu_snapshots = (
            db.query(ProcessSnapshot.cpu_percent)
            .filter(
                ProcessSnapshot.timestamp >= window_start
            )
            .all()
        )

        cpu_values = [
            float(row[0] or 0.0)
            for row in cpu_snapshots
        ]

        max_cpu = max(cpu_values) if cpu_values else 0.0

        cpu_spike = max_cpu >= 80.0
        # ---------------------------------------------------------
        # 3. CURRENT THREAT SCORE
        # ---------------------------------------------------------

        threat_score = 0
        reasons = []

        # Rapid modification activity
        if modification_count >= 10:
            threat_score += 40
            reasons.append(
                "Rapid file modification activity"
            )
        elif modification_count >= 5:
            threat_score += 20
            reasons.append(
                "Elevated file modification activity"
            )

        # Mass rename activity
        if rename_count >= 3:
            threat_score += 30
            reasons.append(
                "Mass file rename activity"
            )
        elif rename_count >= 1:
            threat_score += 10
            reasons.append(
                "File rename activity detected"
            )

        # High entropy
        if average_entropy >= 7.0:
            threat_score += 25
            reasons.append(
                "High file entropy detected"
            )

        # Suspicious extensions
        if suspicious_extension_count > 0:
            threat_score += 20
            reasons.append(
                "Suspicious file extensions detected"
            )
        if cpu_spike:
            threat_score += 15
            reasons.append(
                f"CPU spike detected ({max_cpu:.1f}%)"
            )

        threat_score = min(threat_score, 100)

        if threat_score >= 70:
            threat_level = "CRITICAL"
        elif threat_score >= 40:
            threat_level = "WARNING"
        elif threat_score > 0:
            threat_level = "LOW"
        else:
            threat_level = "NORMAL"

        # ---------------------------------------------------------
        # 4. TIME SINCE LAST FILE ACTIVITY
        # ---------------------------------------------------------

        if recent_events:
            last_activity = recent_events[-1].timestamp
            seconds_since_activity = max(
                0,
                int(
                    (now - last_activity).total_seconds()
                )
            )
        else:
            seconds_since_activity = None

        # ---------------------------------------------------------
        # 5. HISTORICAL FILE ACTIVITY TIMELINE
        # ---------------------------------------------------------
        # The current threat score uses 60 seconds.
        # The dashboard chart uses the last 15 minutes so that
        # previous activity remains visible when the system is idle.

        chart_start = now - timedelta(minutes=15)

        chart_events = (
            db.query(Event)
            .filter(Event.timestamp >= chart_start)
            .order_by(Event.timestamp.asc())
            .all()
        )

        timeline = []

        # 12 buckets × 25 seconds = 5 minutes
        bucket_size = 75

        for bucket_number in range(12):

            bucket_start = chart_start + timedelta(
                seconds=bucket_number * bucket_size
            )

            bucket_end = bucket_start + timedelta(
                seconds=bucket_size
            )

            bucket_events = [
                event
                for event in chart_events
                if bucket_start <= event.timestamp < bucket_end
            ]

            bucket_modifications = sum(
                1
                for event in bucket_events
                if event.event_type == "MODIFY"
            )

            bucket_renames = sum(
                1
                for event in bucket_events
                if event.event_type == "RENAME"
            )

            bucket_creates = sum(
                1
                for event in bucket_events
                if event.event_type == "CREATE"
            )

            bucket_deletes = sum(
                1
                for event in bucket_events
                if event.event_type == "DELETE"
            )

            # Activity score for visualization
            bucket_score = 0

            if bucket_modifications >= 10:
                bucket_score += 40
            elif bucket_modifications >= 5:
                bucket_score += 20

            if bucket_renames >= 3:
                bucket_score += 30
            elif bucket_renames >= 1:
                bucket_score += 10

            bucket_score = min(bucket_score, 100)

            timeline.append({
                "time": bucket_end.strftime("%H:%M:%S"),
                "modifications": bucket_modifications,
                "renames": bucket_renames,
                "creates": bucket_creates,
                "deletes": bucket_deletes,
                "score": bucket_score,
            })

        # ---------------------------------------------------------
        # 6. HISTORICAL CPU TELEMETRY
        # ---------------------------------------------------------
        # Use the 15 for the dashboard.
        #
        # Ignore zero CPU readings when calculating the displayed
        # average. A large number of idle processes can otherwise
        # make the chart appear permanently stuck at 0%.

        cpu_start = now - timedelta(minutes=15)

        process_snapshots = (
            db.query(
                ProcessSnapshot.timestamp,
                ProcessSnapshot.cpu_percent
            )
            .filter(
                ProcessSnapshot.timestamp >= cpu_start
            )
            .order_by(
                ProcessSnapshot.timestamp.asc()
            )
            .all()
        )

        cpu_buckets = {}

        for snapshot in process_snapshots:

            timestamp = snapshot.timestamp

            elapsed_seconds = (
                timestamp - cpu_start
            ).total_seconds()

            bucket_number = int(
                elapsed_seconds // 75
            )

            if bucket_number < 0:
                continue

            if bucket_number > 11:
                bucket_number = 11

            cpu_value = float(
                snapshot.cpu_percent or 0.0
            )

            # Ignore completely idle process readings.
            if cpu_value <= 0:
                continue

            if bucket_number not in cpu_buckets:
                cpu_buckets[bucket_number] = []

            cpu_buckets[bucket_number].append(
                cpu_value
            )

        cpu_timeline = []

        for bucket_number in range(12):

            bucket_end = cpu_start + timedelta(
                seconds=(bucket_number + 1) * 75
            )

            values = cpu_buckets.get(
                bucket_number,
                []
            )

            if values:

                average_cpu = (
                    sum(values) / len(values)
                )

                cpu_timeline.append({
                    "time": bucket_end.strftime("%H:%M:%S"),
                    "cpu": round(
                        average_cpu,
                        2
                    )
                })

            else:

                cpu_timeline.append({
                    "time": bucket_end.strftime("%H:%M:%S"),
                    "cpu": 0
                })
        # ---------------------------------------------------------
        # 7. TOP MODIFIED FILES
        # ---------------------------------------------------------

        modified_counter = Counter(
            event.file_path
            for event in modifications
        )

        top_modified_files = [
            {
                "file": path,
                "count": count
            }
            for path, count
            in modified_counter.most_common(5)
        ]

        # ---------------------------------------------------------
        # 8. RECENT ALERTS
        # ---------------------------------------------------------

        recent_alerts = (
            db.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(5)
            .all()
        )

        alerts_data = [
            {
                "id": alert.id,
                "severity": alert.severity,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
            }
            for alert in recent_alerts
        ]
        # ---------------------------------------------------------
        # 8.5. RECENT INCIDENTS
        # ---------------------------------------------------------

        recent_incidents = (
            db.query(Incident)
            .order_by(Incident.timestamp.desc())
            .limit(5)
            .all()
        )

        incidents_data = [
            {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "timestamp": incident.timestamp.isoformat(),
            }
            for incident in recent_incidents
        ]
        # ---------------------------------------------------------
        # 9. RECENT EVENTS
        # ---------------------------------------------------------

        latest_events = (
            db.query(Event)
            .order_by(Event.timestamp.desc())
            .limit(15)
            .all()
        )

        events_data = [
            {
                "event_type": event.event_type,
                "file_path": event.file_path,
                "extension": event.extension,
                "timestamp": event.timestamp.isoformat(),
            }
            for event in latest_events
        ]

        # ---------------------------------------------------------
        # 10. DATABASE STATISTICS
        # ---------------------------------------------------------

        total_events = db.query(Event).count()
        total_processes = db.query(ProcessSnapshot).count()
        total_alerts = db.query(Alert).count()
        total_incidents = db.query(Incident).count()

        # ---------------------------------------------------------
        # 11. LIVE STATUS
        # ---------------------------------------------------------

        if seconds_since_activity is None:
            activity_status = "IDLE"
        elif seconds_since_activity <= 5:
            activity_status = "ACTIVE"
        elif seconds_since_activity <= 20:
            activity_status = "RECENT"
        else:
            activity_status = "IDLE"

        return {
            "timestamp": now.isoformat(),

            "threat": {
                "score": threat_score,
                "level": threat_level,
                "reasons": reasons,
                "activity_status": activity_status,
                "seconds_since_activity": seconds_since_activity,
            },

            "live_activity": {
                "modifications": modification_count,
                "renames": rename_count,
                "creates": len(creates),
                "deletes": len(deletes),
                "suspicious_extensions": suspicious_extension_count,
                "average_entropy": round(
                    average_entropy,
                    3
                ),
                "max_cpu": round(
                    max_cpu,
                    2
                ),
                "cpu_spike": cpu_spike,
            },

            "statistics": {
                "events": total_events,
                "process_snapshots": total_processes,
                "alerts": total_alerts,
                "incidents": total_incidents,
            },

            "recent_alerts": alerts_data,

            "recent_events": events_data,

            "recent_incidents": incidents_data,

            "top_modified_files": top_modified_files,

            "charts": {
                "activity": timeline,
                "cpu": cpu_timeline,
            },
        }

    finally:
        db.close()

@app.post("/reports/{incident_id}/generate")
def generate_incident_report(incident_id: int):
    manager = ReportManager()

    json_file = manager.generate_json(incident_id)
    csv_file = manager.generate_csv(incident_id)
    html_file = manager.generate_html(incident_id)

    return {
        "status": "success",
        "incident_id": incident_id,
        "reports": {
            "json": str(json_file),
            "csv": str(csv_file),
            "html": str(html_file),
        },
    }

@app.get("/reports/{incident_id}/html")
def view_incident_report(incident_id: int):

    report_file = (
        Path("data/reports")
        / f"incident_{incident_id}.html"
    )

    if not report_file.exists():

        raise HTTPException(
            status_code=404,
            detail="Report not found. Generate the report first."
        )

    return FileResponse(
        report_file,
        media_type="text/html"
    )