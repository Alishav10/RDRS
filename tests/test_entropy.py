from pathlib import Path
import os

from app.core.entropy import calculate_entropy, calculate_file_entropy


def test_empty_data_entropy():
    assert calculate_entropy(b"") == 0.0


def test_repeated_data_has_zero_entropy():
    data = b"A" * 1000

    entropy = calculate_entropy(data)

    assert entropy == 0.0


def test_random_data_has_high_entropy():
    data = os.urandom(65536)

    entropy = calculate_entropy(data)

    assert entropy > 7.5


def test_file_entropy():
    test_file = Path("data/sandbox/test.txt")

    test_file.write_text(
        "This is a simple text file for RDRS entropy testing.",
        encoding="utf-8",
    )

    entropy = calculate_file_entropy(test_file)

    assert entropy < 6.0