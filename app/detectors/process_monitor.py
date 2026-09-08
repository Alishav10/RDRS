import time
from datetime import datetime

import psutil

from app.database.database import SessionLocal
from app.database.models import ProcessSnapshot


class ProcessMonitor:
    """
    Collects information about currently running processes
    and saves snapshots to the RDRS database.
    """

    def __init__(self):
        self.snapshot_count = 0

    def collect_snapshot(self):
        """
        Collect information about all currently running processes.

        CPU usage is measured using two non-blocking psutil
        measurements separated by a short interval. This avoids
        the common problem where the first cpu_percent() reading
        is always 0.0.
        """

        processes = []

        # ---------------------------------------------------------
        # 1. GET CURRENT PROCESSES
        # ---------------------------------------------------------

        process_objects = []

        for process in psutil.process_iter(
            [
                "pid",
                "name",
                "memory_percent",
                "exe",
                "ppid",
            ]
        ):
            try:
                # First CPU measurement establishes the baseline.
                process.cpu_percent(interval=None)

                process_objects.append(process)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        # ---------------------------------------------------------
        # 2. SHORT CPU MEASUREMENT INTERVAL
        # ---------------------------------------------------------

        time.sleep(0.1)

        # ---------------------------------------------------------
        # 3. COLLECT PROCESS INFORMATION
        # ---------------------------------------------------------

        for process in process_objects:

            try:
                info = process.info

                # Second CPU measurement gives us the CPU usage
                # since the baseline measurement.
                cpu_percent = process.cpu_percent(
                    interval=None
                )

                # -------------------------------------------------
                # Parent process
                # -------------------------------------------------

                parent_name = ""

                try:
                    parent_pid = info["ppid"]

                    if parent_pid:
                        parent = psutil.Process(parent_pid)
                        parent_name = parent.name()
                    else:
                        parent_name = "Unknown"

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    parent_name = "Unknown"

                # -------------------------------------------------
                # Disk write information
                # -------------------------------------------------

                disk_writes = 0

                try:
                    io_info = process.io_counters()

                    if io_info:
                        disk_writes = io_info.write_bytes

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    disk_writes = 0

                # -------------------------------------------------
                # Build process snapshot
                # -------------------------------------------------

                process_data = {
                    "pid": info["pid"],
                    "name": info["name"] or "Unknown",

                    "cpu_percent": round(
                        cpu_percent,
                        2
                    ),

                    "memory_percent": (
                        info["memory_percent"] or 0.0
                    ),

                    "disk_writes": disk_writes,

                    "executable_path": (
                        info["exe"] or "Unknown"
                    ),

                    "parent_pid": info["ppid"],

                    "parent_name": parent_name,

                    "timestamp": datetime.now(),
                }

                processes.append(process_data)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                # Process may disappear between measurements.
                continue

        self.snapshot_count += 1

        return processes

    def save_snapshot(self, processes):
        """
        Save one process snapshot to the SQLite database.
        """

        db = SessionLocal()

        try:
            for process in processes:

                snapshot = ProcessSnapshot(
                    pid=process["pid"],
                    name=process["name"],
                    cpu_percent=process["cpu_percent"],
                    memory_percent=process["memory_percent"],
                    disk_writes=process["disk_writes"],
                    executable_path=process["executable_path"],
                    parent_pid=process["parent_pid"],
                    parent_name=process["parent_name"],
                    timestamp=process["timestamp"],
                )

                db.add(snapshot)

            db.commit()

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

    def print_snapshot(self):
        """
        Collect, display, and save the current process snapshot.
        """

        processes = self.collect_snapshot()

        # Save processes to database
        self.save_snapshot(processes)

        print()
        print("=" * 80)

        print(
            f"PROCESS SNAPSHOT #{self.snapshot_count} "
            f"| {datetime.now():%Y-%m-%d %H:%M:%S}"
        )

        print("=" * 80)

        print(f"Processes found: {len(processes)}")
        print("Saved to database: YES")
        print()

        for process in processes[:20]:

            print(
                f"PID={process['pid']:<6} "
                f"NAME={process['name'][:25]:<25} "
                f"CPU={process['cpu_percent']:>5.1f}% "
                f"MEM={process['memory_percent']:>5.1f}% "
                f"PARENT={process['parent_name'][:20]}"
            )

        if len(processes) > 20:
            print(
                f"\n... and {len(processes) - 20} more processes."
            )


def main():

    monitor = ProcessMonitor()

    print("=" * 80)
    print("RDRS PROCESS MONITOR")
    print("=" * 80)
    print("Collecting and saving process snapshots every 5 seconds.")
    print("Press CTRL+C to stop.")

    try:

        while True:

            monitor.print_snapshot()

            time.sleep(5)

    except KeyboardInterrupt:

        print("\nProcess monitor stopped.")


if __name__ == "__main__":
    main()