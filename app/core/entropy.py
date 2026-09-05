import math
from pathlib import Path
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy for a sequence of bytes.

    Returns a value between 0.0 and 8.0.

    0.0 = completely predictable data
    8.0 = maximally random byte distribution
    """

    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_file_entropy(
    file_path: str | Path,
    sample_size: int = 65536,
) -> float:
    """
    Calculate entropy using only the first sample_size bytes
    of a file.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Path is not a file: {file_path}"
        )

    with file_path.open("rb") as file:
        data = file.read(sample_size)

    return calculate_entropy(data)