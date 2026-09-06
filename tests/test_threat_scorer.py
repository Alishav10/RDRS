from app.detectors.threat_scorer import ThreatScorer


def test_no_signals_is_normal():

    scorer = ThreatScorer()

    result = scorer.calculate()

    assert result.score == 0
    assert result.level == "NORMAL"


def test_rapid_encryption_score():

    scorer = ThreatScorer()

    result = scorer.calculate(
        rapid_encryption=True
    )

    assert result.score == 40
    assert result.level == "WARNING"


def test_multiple_signals_create_critical_score():

    scorer = ThreatScorer()

    result = scorer.calculate(
        rapid_encryption=True,
        mass_rename=True,
        high_entropy=True,
    )

    assert result.score == 95
    assert result.level == "CRITICAL"


def test_score_is_capped_at_100():

    scorer = ThreatScorer()

    result = scorer.calculate(
        rapid_encryption=True,
        mass_rename=True,
        high_entropy=True,
        cpu_spike=True,
        unknown_program=True,
    )

    assert result.score == 100
    assert result.level == "CRITICAL"


def test_warning_range():

    scorer = ThreatScorer()

    result = scorer.calculate(
        rapid_encryption=True
    )

    assert 40 <= result.score < 70
    assert result.level == "WARNING"


def test_critical_boundary():

    scorer = ThreatScorer()

    # 40 + 30 = 70
    result = scorer.calculate(
        rapid_encryption=True,
        mass_rename=True,
    )

    assert result.score == 70
    assert result.level == "CRITICAL"