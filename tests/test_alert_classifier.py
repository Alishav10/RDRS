from app.detectors.detection_engine import DetectionSignal
from app.detectors.alert_classifier import AlertClassifier


def make_signal(
    rapid=False,
    rename=False,
    entropy=False,
    extension_changes=0,
    dangerous=False,
):
    return DetectionSignal(
        files_modified=10 if rapid else 0,
        renames=3 if rename else 0,
        extension_changes=extension_changes,
        average_entropy=7.5 if entropy else 0.0,
        window_seconds=60,
        dangerous_burst=dangerous,
        rapid_encryption=rapid,
        mass_rename=rename,
        high_entropy=entropy,
        threat_score=95 if rapid and rename and entropy else 0,
        threat_level="CRITICAL"
        if rapid and rename and entropy
        else "NORMAL",
        scoring_reasons=[],
        reasons=[],
    )


def test_possible_ransomware():

    classifier = AlertClassifier()

    signal = make_signal(
        rapid=True,
        rename=True,
        entropy=True,
        dangerous=True,
    )

    result = classifier.classify(signal)

    assert result.classification == "POSSIBLE_RANSOMWARE"
    assert result.title == "Possible Ransomware Attack"


def test_rapid_file_modification():

    classifier = AlertClassifier()

    signal = make_signal(
        rapid=True,
        dangerous=True,
    )

    result = classifier.classify(signal)

    assert result.classification == "RAPID_FILE_MODIFICATION"


def test_mass_file_rename():

    classifier = AlertClassifier()

    signal = make_signal(
        rename=True,
        dangerous=True,
    )

    result = classifier.classify(signal)

    assert result.classification == "MASS_FILE_RENAME"


def test_high_entropy():

    classifier = AlertClassifier()

    signal = make_signal(
        entropy=True,
        dangerous=True,
    )

    result = classifier.classify(signal)

    assert result.classification == "HIGH_ENTROPY_ACTIVITY"


def test_extension_change():

    classifier = AlertClassifier()

    signal = make_signal(
        extension_changes=2,
        dangerous=True,
    )

    result = classifier.classify(signal)

    assert result.classification == "SUSPICIOUS_EXTENSION_ACTIVITY"


def test_normal_activity():

    classifier = AlertClassifier()

    signal = make_signal()

    result = classifier.classify(signal)

    assert result.classification == "NORMAL"