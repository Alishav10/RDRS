import threading
import time

from app.core.logging_config import setup_logging
from app.detectors.file_monitor import FileMonitor
from app.detectors.process_monitor import ProcessMonitor


def run_file_monitor():
    """
    Run the file monitoring system.
    """

    monitor = FileMonitor()
    monitor.start()


def run_process_monitor():
    """
    Run the process monitoring system.
    """

    monitor = ProcessMonitor()

    try:

        while True:

            monitor.print_snapshot()

            time.sleep(5)

    except KeyboardInterrupt:

        print("\nProcess monitoring stopped.")


def main():

    setup_logging()

    print("=" * 80)
    print("RDRS - RANSOMWARE DETECTION AND RESPONSE SYSTEM")
    print("=" * 80)

    print("\nStarting monitoring components...")
    print("File monitoring: ACTIVE")
    print("Process monitoring: ACTIVE")
    print("Database: SQLite")
    print("\nPress CTRL+C to stop RDRS.\n")

    # Create threads
    file_thread = threading.Thread(
        target=run_file_monitor,
        daemon=True,
    )

    process_thread = threading.Thread(
        target=run_process_monitor,
        daemon=True,
    )

    # Start both monitors
    file_thread.start()
    process_thread.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\n")
        print("=" * 80)
        print("RDRS STOPPED")
        print("=" * 80)


if __name__ == "__main__":
    main()