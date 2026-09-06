from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.config import config
from app.core.logging_config import get_event_logger
from app.database.database import SessionLocal
from app.database.models import Event


@dataclass
class FileEvent:
    event_type: str
    file_path: str
    timestamp: datetime
    extension: str
    old_path: Optional[str] = None


class RDRSEventHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()

        self.event_count = 0
        self.event_logger = get_event_logger()

    def _create_event(
        self,
        event_type: str,
        file_path: str,
        old_path: Optional[str] = None,
    ) -> FileEvent:

        path = Path(file_path)

        return FileEvent(
            event_type=event_type,
            file_path=str(path),
            timestamp=datetime.now(),
            extension=path.suffix.lower(),
            old_path=old_path,
        )

    def on_created(self, event):

        if event.is_directory:
            return

        file_event = self._create_event(
            "CREATE",
            event.src_path,
        )

        self._process_event(file_event)

    def on_modified(self, event):

        if event.is_directory:
            return

        file_event = self._create_event(
            "MODIFY",
            event.src_path,
        )

        self._process_event(file_event)

    def on_deleted(self, event):

        if event.is_directory:
            return

        file_event = self._create_event(
            "DELETE",
            event.src_path,
        )

        self._process_event(file_event)

    def on_moved(self, event):

        if event.is_directory:
            return

        file_event = self._create_event(
            "RENAME",
            event.dest_path,
            old_path=event.src_path,
        )

        self._process_event(file_event)

    def _save_to_database(self, file_event: FileEvent):

        db = SessionLocal()

        try:

            event_record = Event(
                event_type=file_event.event_type,
                file_path=file_event.file_path,
                timestamp=file_event.timestamp,
                extension=file_event.extension,
                old_path=file_event.old_path,
            )

            db.add(event_record)

            db.commit()

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

    def _process_event(self, file_event: FileEvent):

        self.event_count += 1

        print(
            f"[{file_event.timestamp:%H:%M:%S}] "
            f"{file_event.event_type:<8} "
            f"{file_event.file_path} "
            f"(count={self.event_count})"
        )

        # Save event to database
        try:

            self._save_to_database(file_event)

        except Exception as error:

            print(
                f"[DATABASE ERROR] "
                f"Could not save event: {error}"
            )

        # Save event to log file
        self.event_logger.info(
            f"{file_event.event_type} | "
            f"path={file_event.file_path} | "
            f"extension={file_event.extension}"
        )

        if file_event.old_path:

            self.event_logger.info(
                f"RENAME_SOURCE | "
                f"old_path={file_event.old_path} | "
                f"new_path={file_event.file_path}"
            )


class FileMonitor:

    def __init__(self):

        self.observer = Observer()

        self.handler = RDRSEventHandler()

    def start(self):

        watch_folders = config["monitoring"]["watch_folders"]

        if not watch_folders:

            raise ValueError(
                "No watch folders configured."
            )

        for folder in watch_folders:

            path = Path(folder)

            path.mkdir(
                parents=True,
                exist_ok=True,
            )

            print(
                f"Watching: {path.resolve()}"
            )

            self.observer.schedule(
                self.handler,
                str(path),
                recursive=True,
            )

        self.observer.start()

        print("\nRDRS file monitor started.")
        print("Press CTRL+C to stop.\n")

        try:

            while True:

                time.sleep(1)

        except KeyboardInterrupt:

            print(
                "\nStopping RDRS file monitor..."
            )

            self.observer.stop()

        self.observer.join()


if __name__ == "__main__":

    monitor = FileMonitor()

    monitor.start()