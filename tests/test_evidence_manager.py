from pathlib import Path

from app.response.evidence_manager import EvidenceManager


def test_evidence_is_copied_without_changing_original(
    tmp_path,
):

    original = (
        tmp_path
        / "important_test_file.txt"
    )

    original_content = (
        "Safe RDRS evidence test"
    )

    original.write_text(
        original_content,
        encoding="utf-8",
    )

    original_before = (
        original.read_bytes()
    )

    manager = EvidenceManager()

    # Use a temporary incident ID.
    incident_id = 999999

    copied_files = manager.quarantine_files(
        [str(original)],
        incident_id,
    )

    # ----------------------------------------
    # COPY WAS CREATED
    # ----------------------------------------

    assert len(copied_files) == 1

    copied_file = Path(
        copied_files[0]
    )

    assert copied_file.exists()

    # ----------------------------------------
    # COPIED CONTENT IS CORRECT
    # ----------------------------------------

    assert (
        copied_file.read_text(
            encoding="utf-8"
        )
        == original_content
    )

    # ----------------------------------------
    # ORIGINAL STILL EXISTS
    # ----------------------------------------

    assert original.exists()

    # ----------------------------------------
    # ORIGINAL CONTENT IS UNCHANGED
    # ----------------------------------------

    original_after = (
        original.read_bytes()
    )

    assert original_before == original_after