from dataclasses import dataclass


@dataclass
class AlertClassification:
    """
    Represents the classification of detected suspicious activity.
    """

    classification: str
    title: str
    summary: str
    recommendations: list[str]


class AlertClassifier:
    """
    Classifies ransomware-related activity based on
    the signals produced by DetectionEngine.
    """

    def classify(self, signal):
        """
        Classify the detected activity using existing
        DetectionSignal values.

        The strongest combination of ransomware-like
        indicators receives the highest classification.
        """

        recommendations = []

        # -------------------------------------------------
        # 1. POSSIBLE RANSOMWARE
        # -------------------------------------------------

        if (
            signal.rapid_encryption
            and signal.mass_rename
            and signal.high_entropy
        ):

            return AlertClassification(
                classification="POSSIBLE_RANSOMWARE",
                title="Possible Ransomware Attack",
                summary=(
                    "Multiple strong ransomware-like indicators "
                    "were detected simultaneously."
                ),
                recommendations=[
                    "Isolate the affected endpoint from the network.",
                    "Preserve original evidence for investigation.",
                    "Review the process responsible for the activity.",
                    "Review affected files and recent file changes.",
                    "Check authentication and system logs.",
                    "Verify backups before restoration.",
                    "Continue monitoring until the incident is resolved.",
                ],
            )

        # -------------------------------------------------
        # 2. RAPID MODIFICATION + MASS RENAME
        # -------------------------------------------------

        if (
            signal.rapid_encryption
            and signal.mass_rename
        ):

            return AlertClassification(
                classification="RANSOMWARE_LIKE_FILE_ACTIVITY",
                title="Ransomware-Like File Activity",
                summary=(
                    "Rapid file modification and mass rename "
                    "activity were detected together."
                ),
                recommendations=[
                    "Review the process responsible for the changes.",
                    "Inspect recently modified and renamed files.",
                    "Check for additional extension changes.",
                    "Monitor for high-entropy file activity.",
                    "Escalate if additional ransomware indicators appear.",
                ],
            )

        # -------------------------------------------------
        # 3. RAPID FILE MODIFICATION
        # -------------------------------------------------

        if signal.rapid_encryption:

            return AlertClassification(
                classification="RAPID_FILE_MODIFICATION",
                title="Rapid File Modification",
                summary=(
                    "A high number of unique files were modified "
                    "within the detection window."
                ),
                recommendations=[
                    "Identify the process modifying the files.",
                    "Review the affected files.",
                    "Check whether the activity is expected.",
                    "Monitor for file renames and extension changes.",
                ],
            )

        # -------------------------------------------------
        # 4. MASS FILE RENAME
        # -------------------------------------------------

        if signal.mass_rename:

            return AlertClassification(
                classification="MASS_FILE_RENAME",
                title="Mass File Rename Activity",
                summary=(
                    "Multiple files were renamed within "
                    "the detection window."
                ),
                recommendations=[
                    "Review the source and destination file names.",
                    "Check for suspicious extension changes.",
                    "Identify the process responsible for the renames.",
                    "Monitor for additional file modifications.",
                ],
            )

        # -------------------------------------------------
        # 5. HIGH ENTROPY
        # -------------------------------------------------

        if signal.high_entropy:

            return AlertClassification(
                classification="HIGH_ENTROPY_ACTIVITY",
                title="High Entropy File Activity",
                summary=(
                    "Modified files exhibited unusually "
                    "high average entropy."
                ),
                recommendations=[
                    "Inspect the affected files.",
                    "Determine whether compression or encryption is expected.",
                    "Identify the process responsible for the changes.",
                    "Monitor for mass rename or rapid modification activity.",
                ],
            )

        # -------------------------------------------------
        # 6. EXTENSION CHANGES
        # -------------------------------------------------

        if signal.extension_changes > 0:

            return AlertClassification(
                classification="SUSPICIOUS_EXTENSION_ACTIVITY",
                title="Suspicious File Extension Changes",
                summary=(
                    "File extensions changed during "
                    "the detection window."
                ),
                recommendations=[
                    "Review the old and new file extensions.",
                    "Identify the process responsible for the changes.",
                    "Check whether the extension changes are expected.",
                    "Monitor for additional ransomware-like behavior.",
                ],
            )

        # -------------------------------------------------
        # 7. GENERAL SUSPICIOUS FILE ACTIVITY
        # -------------------------------------------------

        if signal.dangerous_burst:

            return AlertClassification(
                classification="SUSPICIOUS_FILE_ACTIVITY",
                title="Suspicious File Activity",
                summary=(
                    "Unusual file activity was detected "
                    "within the monitoring window."
                ),
                recommendations=[
                    "Review recent file activity.",
                    "Identify the process responsible.",
                    "Continue monitoring for additional indicators.",
                ],
            )

        # -------------------------------------------------
        # 8. NORMAL
        # -------------------------------------------------

        return AlertClassification(
            classification="NORMAL",
            title="Normal File Activity",
            summary="No significant ransomware-like activity detected.",
            recommendations=[],
        )