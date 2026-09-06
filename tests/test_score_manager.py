from app.database.database import SessionLocal
from app.database.models import Score
from app.response.score_manager import ScoreManager


def test_threat_score_is_saved():
    manager = ScoreManager()

    score_id = manager.save_score(
        score=95,
        reasons=[
            "Rapid encryption/modification activity (+40)",
            "Mass file rename activity (+30)",
            "High file entropy (+25)",
        ],
    )

    assert score_id is not None

    db = SessionLocal()

    try:
        score_record = (
            db.query(Score)
            .filter(Score.id == score_id)
            .first()
        )

        assert score_record is not None
        assert score_record.score == 95
        assert "High file entropy" in score_record.reason

    finally:
        db.close()