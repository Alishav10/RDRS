from pathlib import Path
import time
import random
import string

SANDBOX = Path("data/sandbox")
SANDBOX.mkdir(parents=True, exist_ok=True)


def clean_sandbox():
    """Remove only files created by this safe simulator."""
    for path in SANDBOX.iterdir():
        if path.is_file():
            path.unlink()


def modify_files(count: int, prefix: str, delay: float = 0.15):
    """Create/modify harmless text files."""
    for i in range(count):
        path = SANDBOX / f"{prefix}_{i}.txt"

        path.write_text(
            f"RDRS SAFE DEMO FILE {i}\n"
            f"Modified at {time.time()}\n",
            encoding="utf-8",
        )

        print(f"[MODIFY] {path}")
        time.sleep(delay)


def rename_files(count: int, prefix: str = "rename"):
    """Safely rename harmless files."""
    for i in range(count):
        source = SANDBOX / f"{prefix}_{i}.txt"
        target = SANDBOX / f"{prefix}_{i}.demo.txt"

        source.write_text(
            "RDRS SAFE DEMONSTRATION FILE\n",
            encoding="utf-8",
        )

        source.rename(target)

        print(f"[RENAME] {source} -> {target}")
        time.sleep(0.2)


def create_high_entropy_files(count: int):
    """
    Create harmless files containing random data.
    This simulates high-entropy content without encryption.
    """
    characters = string.ascii_letters + string.digits + string.punctuation

    for i in range(count):
        path = SANDBOX / f"entropy_{i}.bin"

        data = "".join(
            random.choice(characters)
            for _ in range(4096)
        )

        path.write_text(data, encoding="utf-8")

        print(f"[HIGH ENTROPY] {path}")
        time.sleep(0.15)


def extension_change():
    """Safely create and rename a file to demonstrate extension changes."""
    source = SANDBOX / "document.txt"
    target = SANDBOX / "document.demo"

    source.write_text(
        "RDRS SAFE EXTENSION TEST\n",
        encoding="utf-8",
    )

    source.rename(target)

    print(f"[EXTENSION] {source} -> {target}")


def normal_activity():
    print("\n=== NORMAL ACTIVITY ===")
    modify_files(2, "normal", delay=1.0)


def rapid_modification():
    print("\n=== RAPID FILE MODIFICATION ===")
    modify_files(6, "rapid", delay=0.1)


def mass_rename():
    print("\n=== MASS FILE RENAME ===")
    rename_files(3, "massrename")


def high_entropy():
    print("\n=== HIGH ENTROPY ACTIVITY ===")
    create_high_entropy_files(3)


def suspicious_extension():
    print("\n=== SUSPICIOUS EXTENSION ACTIVITY ===")
    extension_change()


def ransomware_like():
    print("\n=== RANSOMWARE-LIKE ACTIVITY ===")

    modify_files(10, "ransom", delay=0.1)

    rename_files(3, "ransom")


def possible_ransomware():
    print("\n=== POSSIBLE RANSOMWARE ACTIVITY ===")

    modify_files(10, "critical", delay=0.1)

    create_high_entropy_files(3)

    rename_files(3, "critical")


def show_menu():
    print("\n" + "=" * 55)
    print("       RDRS SAFE SIMULATION")
    print("=" * 55)
    print("Only harmless files inside data/sandbox are used.")
    print()
    print("1. Normal activity")
    print("2. Rapid file modification")
    print("3. Mass file rename")
    print("4. High entropy activity")
    print("5. Suspicious extension activity")
    print("6. Ransomware-like activity")
    print("7. Possible ransomware activity")
    print("8. Clean sandbox")
    print("0. Exit")
    print("=" * 55)


while True:
    show_menu()

    choice = input("\nSelect scenario: ").strip()

    if choice == "1":
        normal_activity()

    elif choice == "2":
        rapid_modification()

    elif choice == "3":
        mass_rename()

    elif choice == "4":
        high_entropy()

    elif choice == "5":
        suspicious_extension()

    elif choice == "6":
        ransomware_like()

    elif choice == "7":
        possible_ransomware()

    elif choice == "8":
        clean_sandbox()
        print("[CLEAN] Sandbox cleaned.")

    elif choice == "0":
        print("\nSimulation ended.")
        break

    else:
        print("\nInvalid choice.")

    print("\nScenario complete.")