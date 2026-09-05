# from pathlib import Path
# import os

# from app.core.entropy import calculate_entropy, calculate_file_entropy


# def main():

#     print("RDRS Entropy Detector")
#     print("=====================")

#     # Predictable data
#     predictable = b"A" * 10000

#     print(
#         f"Repeated A entropy: "
#         f"{calculate_entropy(predictable):.4f}"
#     )

#     # Normal text
#     text = (
#         b"RDRS is a defensive ransomware detection system. "
#         b"It monitors file activity and calculates entropy."
#         * 100
#     )

#     print(
#         f"Text entropy: "
#         f"{calculate_entropy(text):.4f}"
#     )

#     # Random bytes
#     random_data = os.urandom(65536)

#     print(
#         f"Random data entropy: "
#         f"{calculate_entropy(random_data):.4f}"
#     )

#     # Actual file
#     sandbox_file = Path("data/sandbox/normal.txt")

#     if sandbox_file.exists():
#         print(
#             f"normal.txt entropy: "
#             f"{calculate_file_entropy(sandbox_file):.4f}"
#         )


# if __name__ == "__main__":
#     main()

from app.core.logging_config import setup_logging
from app.detectors.file_monitor import FileMonitor


def main():

    setup_logging()

    print("=" * 50)
    print("RDRS - Ransomware Detection and Response System")
    print("=" * 50)

    monitor = FileMonitor()

    monitor.start()


if __name__ == "__main__":
    main()