from pathlib import Path
import time

SANDBOX = Path("data/sandbox")
SANDBOX.mkdir(parents=True, exist_ok=True)


def modify_files(count: int, prefix: str):
    for i in range(count):
        path = SANDBOX / f"{prefix}_{i}.txt"

        path.write_text(
            f"RDRS SAFE DEMO FILE {i}\n"
            f"Modified at {time.time()}\n",
            encoding="utf-8",
        )

        print(f"[MODIFY] {path}")
        time.sleep(0.15)


def rename_files(count: int):
    for i in range(count):
        source = SANDBOX / f"critical_{i}.txt"
        target = SANDBOX / f"critical_{i}.demo.txt"

        source.write_text(
            "RDRS SAFE DEMONSTRATION FILE\n",
            encoding="utf-8",
        )

        source.rename(target)

        print(f"[RENAME] {source} -> {target}")
        time.sleep(0.2)


print("\n=== RDRS SAFE SIMULATION ===")
print("Only harmless files inside data/sandbox will be used.")
print()

print("Phase 1: Creating moderate file activity...")
modify_files(5, "warning")

print("\nWaiting 3 seconds...")
time.sleep(3)

print("\nPhase 2: Creating additional activity...")
modify_files(12, "critical")

print("\nPhase 3: Performing safe file renames...")
rename_files(3)

print("\n=== SIMULATION COMPLETE ===")
print("No real files were encrypted or deleted.")