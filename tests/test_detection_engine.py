import os
from datetime import datetime

from app.detectors.detection_engine import DetectionEngine
from app.detectors.file_monitor import FileEvent


def create_event(
    event_type,
    file_path,
    old_path=None,
):
    return FileEvent(
        event_type=event_type,
        file_path=file_path,
        timestamp=datetime.now(),
        extension=file_path.split(".")[-1],
        old_path=old_path,
    )


def test_normal_activity_stays_below_threshold():

    engine = DetectionEngine()

    event = create_event(
        "MODIFY",
        "data/sandbox/normal.txt",
    )

    signal = engine.add_event(event)

    assert signal.files_modified == 1
    assert signal.dangerous_burst is False


def test_rapid_modifications_trigger_burst():

    engine = DetectionEngine()

    for i in range(10):

        event = create_event(
            "MODIFY",
            f"data/sandbox/file{i}.txt",
        )

        signal = engine.add_event(event)

    assert signal.files_modified == 10
    assert signal.dangerous_burst is True


def test_multiple_modifications_of_same_file_count_once():

    engine = DetectionEngine()

    for _ in range(5):

        event = create_event(
            "MODIFY",
            "data/sandbox/repeated.txt",
        )

        signal = engine.add_event(event)

    assert signal.files_modified == 1
    assert signal.dangerous_burst is False


def test_extension_changes_are_detected():

    engine = DetectionEngine()

    for i in range(3):

        event = create_event(
            "RENAME",
            f"data/sandbox/file{i}.locked",
            old_path=f"data/sandbox/file{i}.docx",
        )

        signal = engine.add_event(event)

    assert signal.renames == 3
    assert signal.extension_changes == 3
    assert signal.dangerous_burst is True


def test_normal_extension_rename_is_not_extension_change():

    engine = DetectionEngine()

    event = create_event(
        "RENAME",
        "data/sandbox/file.txt",
        old_path="data/sandbox/old.txt",
    )

    signal = engine.add_event(event)

    assert signal.renames == 1
    assert signal.extension_changes == 0
    assert signal.dangerous_burst is False

def test_high_entropy_triggers_burst(tmp_path):

    test_file = tmp_path / "high_entropy.bin"

    # Generate safe random test data.
    test_file.write_bytes(
        os.urandom(65536)
    )

    engine = DetectionEngine()

    event = create_event(
        "MODIFY",
        str(test_file),
    )

    signal = engine.add_event(event)

    assert signal.average_entropy > 7.0
    assert signal.dangerous_burst is True
    assert any(
        "entropy" in reason.lower()
        for reason in signal.reasons
    )