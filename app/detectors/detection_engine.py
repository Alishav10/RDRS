from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import config
from app.core.entropy import calculate_file_entropy
from app.detectors.threat_scorer import ThreatScorer


@dataclass
class DetectionSignal:
    """
    Represents the current ransomware-related activity signals.
    """

    files_modified: int
    renames: int
    extension_changes: int
    average_entropy: float
    window_seconds: int
    dangerous_burst: bool
    rapid_encryption: bool
    mass_rename: bool
    high_entropy: bool
    threat_score: int
    threat_level: str
    scoring_reasons: list[str]
    reasons: list[str]


class DetectionEngine:
    """
    Analyzes recent file events using a sliding time window.
    """

    def __init__(self, window_seconds=None):

        self.threat_scorer = ThreatScorer()
        file_config = config["monitoring"]["file_activity"]

        if window_seconds is None:
            window_seconds = file_config[
                "detection_window_seconds"
            ]

        self.window_seconds = window_seconds

        # Store recent events.
        self.events = deque()

        # Thresholds.
        self.modified_threshold = file_config[
            "rapid_change_threshold"
        ]

        self.rename_threshold = file_config[
            "rename_threshold"
        ]

        self.extension_threshold = file_config[
            "suspicious_extension_threshold"
        ]

        self.entropy_threshold = config["monitoring"][
            "entropy"
        ]["suspicious_threshold"]

    def add_event(self, file_event):
        """
        Add a new file event to the sliding window
        and immediately recalculate detection signals.
        """

        self.events.append(file_event)

        self._remove_old_events()

        return self.analyze()

    def _remove_old_events(self):
        """
        Remove events older than the configured window.
        """

        cutoff = datetime.now() - timedelta(
            seconds=self.window_seconds
        )

        while self.events:

            oldest_event = self.events[0]

            if oldest_event.timestamp >= cutoff:
                break

            self.events.popleft()

    def analyze(self) -> DetectionSignal:
        """
        Calculate ransomware-related activity signals.
        """

        self._remove_old_events()

        modified_files = set()

        renames = 0
        extension_changes = 0

        entropy_values = []

        entropy_files = set()

        for event in self.events:

            # ----------------------------------------
            # FILE MODIFICATION
            # ----------------------------------------

            if event.event_type == "MODIFY":

                modified_files.add(
                    event.file_path
                )

                # Calculate entropy once per file
                # during the current window.
                if event.file_path not in entropy_files:

                    entropy = self._calculate_entropy_safely(
                        event.file_path
                    )

                    if entropy is not None:

                        entropy_values.append(
                            entropy
                        )

                        entropy_files.add(
                            event.file_path
                        )

            # ----------------------------------------
            # FILE RENAME
            # ----------------------------------------

            elif event.event_type == "RENAME":

                renames += 1

                if self._is_extension_change(event):

                    extension_changes += 1

        # Number of unique files modified.
        files_modified = len(modified_files)

        # ----------------------------------------
        # AVERAGE ENTROPY
        # ----------------------------------------

        if entropy_values:

            average_entropy = (
                sum(entropy_values)
                / len(entropy_values)
            )

        else:

            average_entropy = 0.0

        # ----------------------------------------
        # DETECTION DECISION
        # ----------------------------------------

        rapid_encryption = (
            files_modified >= self.modified_threshold
        )

        mass_rename = (
            renames >= self.rename_threshold
        )

        high_entropy = (
            average_entropy >= self.entropy_threshold
        )

        threat_score = self.threat_scorer.calculate(
            rapid_encryption=rapid_encryption,
            mass_rename=mass_rename,
            high_entropy=high_entropy,
        )

        dangerous_burst = (
            rapid_encryption
            or mass_rename
            or high_entropy
        )

        reasons = []

        if rapid_encryption:
            reasons.append(
                f"High file modification rate: "
                f"{files_modified} unique files modified "
                f"in {self.window_seconds} seconds"
            )

        if mass_rename:
            reasons.append(
                f"Mass file rename activity: {renames} renames"
            )

        if extension_changes >= self.extension_threshold:
            reasons.append(
                f"Multiple extension changes: "
                f"{extension_changes}"
            )

        if high_entropy:
            reasons.append(
                f"High average file entropy: "
                f"{average_entropy:.2f}"
            )

        if files_modified >= self.modified_threshold:

            dangerous_burst = True

            reasons.append(
                f"High file modification rate: "
                f"{files_modified} unique files modified "
                f"in {self.window_seconds} seconds"
            )

        if extension_changes >= self.extension_threshold:

            dangerous_burst = True

            reasons.append(
                f"Multiple extension changes: "
                f"{extension_changes}"
            )

        if average_entropy >= self.entropy_threshold:

            dangerous_burst = True

            reasons.append(
                f"High average file entropy: "
                f"{average_entropy:.2f}"
            )

        return DetectionSignal(
            files_modified=files_modified,
            renames=renames,
            extension_changes=extension_changes,
            average_entropy=average_entropy,
            window_seconds=self.window_seconds,
            dangerous_burst=dangerous_burst,
            rapid_encryption=rapid_encryption,
            mass_rename=mass_rename,
            high_entropy=high_entropy,
            threat_score=threat_score.score,
            threat_level=threat_score.level,
            scoring_reasons=threat_score.reasons,
            reasons=reasons,
        )

    def _is_extension_change(self, event):
        """
        Determine whether a rename changed the file extension.

        Example:

            document.docx
                    ↓
            document.locked

        This counts as an extension change.
        """

        if not event.old_path:
            return False

        old_extension = Path(
            event.old_path
        ).suffix.lower()

        new_extension = Path(
            event.file_path
        ).suffix.lower()

        return (
            old_extension != new_extension
            and old_extension != ""
            and new_extension != ""
        )

    def _calculate_entropy_safely(self, file_path):
        """
        Calculate entropy without allowing a missing,
        deleted, or inaccessible file to crash detection.
        """

        try:

            path = Path(file_path)

            if not path.exists():
                return None

            if not path.is_file():
                return None

            return calculate_file_entropy(
                path,
                sample_size=config["monitoring"][
                    "entropy"
                ]["sample_size"],
            )

        except (
            OSError,
            PermissionError,
        ):

            return None

    def get_affected_files(self):

            """
            Return unique file paths involved in the
            current detection window.

            This is used by the response system to
            preserve evidence.
            """

            affected_files = []
            seen = set()

            for event in self.events:
                paths = [
                    event.file_path,
                    event.old_path,
                ]

                for file_path in paths:
                    if not file_path:
                        continue

                    if file_path in seen:
                        continue

                    seen.add(file_path)
                    affected_files.append(file_path)

            return affected_files