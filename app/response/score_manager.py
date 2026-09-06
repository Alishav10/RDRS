from datetime import datetime

from app.core.logging_config import get_audit_logger
from app.database.database import SessionLocal
from app.database.models import Score


class ScoreManager:
    """
    Saves calculated threat scores into the RDRS database.
    """

    def __init__(self):
        self.audit_logger = get_audit_logger()

    def save_score(
        self,
        score,
        reasons,
        event_id=None,
        process_id=None,
    ):
        reason_text = "; ".join(reasons)

        db = SessionLocal()

        try:
            score_record = Score(
                event_id=event_id,
                process_id=process_id,
                score=score,
                reason=reason_text,
                timestamp=datetime.now(),
            )

            db.add(score_record)
            db.commit()
            db.refresh(score_record)

            score_id = score_record.id

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

        self.audit_logger.info(
            f"THREAT_SCORE_SAVED | "
            f"score_id={score_id} | "
            f"score={score} | "
            f"reasons={reason_text or 'None'}"
        )

        return score_id