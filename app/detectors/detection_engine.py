from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import config
from app.core.entropy import calculate_file_entropy


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
    reasons: list[str]


class DetectionEngine:
    """
    Analyzes recent file events using a sliding time window.
    """

    def __init__(self, window_seconds=None):

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

        dangerous_burst = False

        reasons = []

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