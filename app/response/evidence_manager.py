from pathlib import Path
import shutil

from app.core.config import config
from app.core.logging_config import get_audit_logger


class EvidenceManager:
    """
    Preserves evidence by copying files into a quarantine
    directory.

    Original files are never modified or deleted.
    """

    def __init__(self):

        response_config = config["response"]

        self.quarantine_directory = Path(
            response_config["quarantine_directory"]
        )

        self.quarantine_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.audit_logger = get_audit_logger()

    def quarantine_files(
        self,
        affected_files,
        incident_id,
    ):
        """
        Copy affected files into an incident-specific
        quarantine directory.

        This function NEVER deletes or modifies originals.
        """

        incident_directory = (
            self.quarantine_directory
            / f"incident_{incident_id}"
        )

        incident_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        copied_files = []

        for file_path in affected_files:

            source = Path(file_path)

            # ----------------------------------------
            # SAFETY CHECK
            # ----------------------------------------

            if not source.exists():

                self.audit_logger.warning(
                    f"EVIDENCE_NOT_FOUND | "
                    f"path={source}"
                )

                continue

            if not source.is_file():

                self.audit_logger.warning(
                    f"EVIDENCE_NOT_FILE | "
                    f"path={source}"
                )

                continue

            # ----------------------------------------
            # COPY ONLY
            # ----------------------------------------

            destination = (
                incident_directory
                / source.name
            )

            try:

                shutil.copy2(
                    source,
                    destination,
                )

                copied_files.append(
                    str(destination)
                )

                self.audit_logger.info(
                    f"EVIDENCE_COPIED | "
                    f"source={source} | "
                    f"destination={destination}"
                )

            except (
                OSError,
                PermissionError,
            ) as error:

                self.audit_logger.error(
                    f"EVIDENCE_COPY_FAILED | "
                    f"source={source} | "
                    f"error={error}"
                )

        return copied_files