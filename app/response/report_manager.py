import csv
import json
from pathlib import Path
from datetime import datetime, timedelta

from jinja2 import Environment, FileSystemLoader

from app.database.database import SessionLocal
from app.database.models import Incident, Event, Score


class ReportManager:
    """
    Generates incident reports in JSON and CSV format.

    Reports are read-only exports. They do not modify
    incident evidence or source files.
    """

    def __init__(self):
        self.report_directory = Path("data/reports")
        self.report_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def _get_incident(self, db, incident_id):
        return (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

    def _get_events(self, db, incident):
        """
        Retrieve events associated with the incident timeframe.

        The incident timestamp is used as the center of the
        investigation window.
        """

        start_time = incident.timestamp - timedelta(seconds=60)
        end_time = incident.timestamp + timedelta(seconds=10)

        return (
            db.query(Event)
            .filter(
                Event.timestamp >= start_time,
                Event.timestamp <= end_time
            )
            .order_by(Event.timestamp.asc())
            .all()
        )

    def _get_score(self, db, incident):
        """
        Get the score closest to the incident timestamp.

        This prevents the report from accidentally using
        the score belonging to a newer incident.
        """

        start_time = incident.timestamp - timedelta(seconds=60)
        end_time = incident.timestamp + timedelta(seconds=10)

        return (
            db.query(Score)
            .filter(
                Score.timestamp >= start_time,
                Score.timestamp <= end_time
            )
            .order_by(Score.timestamp.desc())
            .first()
        )

    def _extract_suspect_process(self, description):
        """
        Extract the suspect process recorded in the
        incident description.
        """

        marker = "Suspect process: "

        for line in description.splitlines():
            if line.startswith(marker):
                value = line[len(marker):].strip()

                if value and value != "Unknown":
                    return value

        return "Unknown"

    def _extract_threat_score(self, description):
        """
        Extract the exact threat score recorded when
        the incident was created.
        """

        marker = "Threat score: "

        for line in description.splitlines():
            if line.startswith(marker):
                value = line[len(marker):].strip()

                try:
                    return float(value)
                except ValueError:
                    pass

        return None

    def _extract_affected_files(self, description):
        """
        Extract affected files directly from the incident
        description.

        This is more reliable than reconstructing affected
        files from database events.
        """

        affected_files = []
        collecting = False

        for line in description.splitlines():

            if line.strip() == "Affected files:":
                collecting = True
                continue

            if collecting:
                line = line.strip()

                if line.startswith("- "):
                    file_path = line[2:].strip()

                    if file_path:
                        affected_files.append(file_path)

                elif line:
                    # Stop if another section begins.
                    break

        return sorted(set(affected_files))

    def _build_timeline(self, events):
        """
        Convert database events into report-friendly
        timeline entries.
        """

        timeline = []

        for event in events:
            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "file_path": event.file_path,
                "extension": event.extension,
                "old_path": event.old_path,
            })

        return timeline

    def _build_report(self, db, incident_id):
        incident = self._get_incident(db, incident_id)

        if not incident:
            raise ValueError(
                f"Incident {incident_id} not found."
            )

        # Get events from the incident timeframe.
        events = self._get_events(
            db,
            incident
        )

        # Get score near the incident timestamp.
        score_record = self._get_score(
            db,
            incident
        )

        # --------------------------------------------------
        # Extract exact information stored in the incident
        # --------------------------------------------------

        suspect_process = self._extract_suspect_process(
            incident.description
        )

        description_score = self._extract_threat_score(
            incident.description
        )

        affected_files = self._extract_affected_files(
            incident.description
        )

        # Prefer the exact score stored in the incident
        # description.
        if description_score is not None:
            threat_score = description_score
        elif score_record:
            threat_score = float(score_record.score)
        else:
            threat_score = 0.0

        # Build event timeline.
        timeline = self._build_timeline(
            events
        )

        report = {
            "report": {
                "title": "RDRS Incident Report",
                "generated_at": datetime.now().isoformat(),
                "incident_id": incident.id,
            },

            "incident": {
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "timestamp": incident.timestamp.isoformat(),
                "description": incident.description,
            },

            "threat_assessment": {
                "score": threat_score,
                "score_range": "0-100",
                "threat_level": incident.severity,
            },

            "suspect_process": suspect_process,

            "affected_files": affected_files,

            "timeline": timeline,

            "recommendations": [
                "Isolate the suspected endpoint from the network.",
                "Preserve original evidence for investigation.",
                "Review the suspect process and its parent process.",
                "Review recent file modification and rename activity.",
                "Check authentication and system logs for related activity.",
                "Verify backups before restoring affected files.",
                "Keep RDRS monitoring enabled until the incident is resolved.",
            ],
        }

        return report

    def generate_json(self, incident_id):
        db = SessionLocal()

        try:
            report = self._build_report(
                db,
                incident_id
            )

            output_file = (
                self.report_directory
                / f"incident_{incident_id}.json"
            )

            with output_file.open(
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    indent=4
                )

            return output_file

        finally:
            db.close()

    def generate_csv(self, incident_id):
        db = SessionLocal()

        try:
            report = self._build_report(
                db,
                incident_id
            )

            output_file = (
                self.report_directory
                / f"incident_{incident_id}.csv"
            )

            with output_file.open(
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow([
                    "Incident ID",
                    "Severity",
                    "Status",
                    "Threat Score",
                    "Suspect Process",
                    "Event Timestamp",
                    "Event Type",
                    "File Path",
                    "Extension",
                    "Old Path",
                ])

                # If timeline events exist, write them.
                if report["timeline"]:

                    for event in report["timeline"]:
                        writer.writerow([
                            report["report"]["incident_id"],
                            report["incident"]["severity"],
                            report["incident"]["status"],
                            report["threat_assessment"]["score"],
                            report["suspect_process"],
                            event["timestamp"],
                            event["event_type"],
                            event["file_path"],
                            event["extension"],
                            event["old_path"] or "",
                        ])

                # If there are no timeline events, still
                # write the affected files recorded in the
                # incident.
                else:

                    for file_path in report["affected_files"]:
                        writer.writerow([
                            report["report"]["incident_id"],
                            report["incident"]["severity"],
                            report["incident"]["status"],
                            report["threat_assessment"]["score"],
                            report["suspect_process"],
                            report["incident"]["timestamp"],
                            "AFFECTED_FILE",
                            file_path,
                            Path(file_path).suffix,
                            "",
                        ])

            return output_file

        finally:
            db.close()

    def generate_html(self, incident_id):
        db = SessionLocal()

        try:
            report = self._build_report(
                db,
                incident_id
            )

            incident_timestamp = datetime.fromisoformat(
                report["incident"]["timestamp"]
            )

            generated_timestamp = datetime.fromisoformat(
                report["report"]["generated_at"]
            )

            template_directory = (
                Path(__file__).resolve().parent
                / "templates"
            )

            environment = Environment(
                loader=FileSystemLoader(
                    template_directory
                ),
                autoescape=True
            )

            template = environment.get_template(
                "incident_report.html"
            )

            html_content = template.render(
                report=report,
                incident_date=incident_timestamp.strftime(
                    "%d %B %Y"
                ),
                incident_time=incident_timestamp.strftime(
                    "%I:%M:%S %p"
                ),
                generated_date=generated_timestamp.strftime(
                    "%d %B %Y"
                ),
                generated_time=generated_timestamp.strftime(
                    "%I:%M:%S %p"
                )
            )

            output_file = (
                self.report_directory
                / f"incident_{incident_id}.html"
            )

            output_file.write_text(
                html_content,
                encoding="utf-8"
            )

            return output_file

        finally:
            db.close()