from dataclasses import dataclass

from app.core.config import config


@dataclass
class ThreatScore:
    """
    Represents the calculated threat score.
    """

    score: int
    level: str
    reasons: list[str]


class ThreatScorer:
    """
    Calculates a transparent 0-100 threat score
    using configurable weighted rules.
    """

    def __init__(self):

        scoring_config = config["threat_scoring"]

        self.weights = scoring_config["weights"]

        self.normal_max = scoring_config["levels"][
            "normal_max"
        ]

        self.warning_max = scoring_config["levels"][
            "warning_max"
        ]

    def calculate(
        self,
        rapid_encryption=False,
        mass_rename=False,
        high_entropy=False,
        cpu_spike=False,
        unknown_program=False,
    ):

        score = 0

        reasons = []

        # ----------------------------------------
        # RAPID ENCRYPTION / MODIFICATION
        # ----------------------------------------

        if rapid_encryption:

            weight = self.weights[
                "rapid_encryption"
            ]

            score += weight

            reasons.append(
                f"Rapid encryption/modification "
                f"activity (+{weight})"
            )

        # ----------------------------------------
        # MASS RENAME
        # ----------------------------------------

        if mass_rename:

            weight = self.weights[
                "mass_rename"
            ]

            score += weight

            reasons.append(
                f"Mass file rename activity "
                f"(+{weight})"
            )

        # ----------------------------------------
        # HIGH ENTROPY
        # ----------------------------------------

        if high_entropy:

            weight = self.weights[
                "high_entropy"
            ]

            score += weight

            reasons.append(
                f"High file entropy "
                f"(+{weight})"
            )

        # ----------------------------------------
        # CPU SPIKE
        # ----------------------------------------

        if cpu_spike:

            weight = self.weights[
                "cpu_spike"
            ]

            score += weight

            reasons.append(
                f"CPU spike detected "
                f"(+{weight})"
            )

        # ----------------------------------------
        # UNKNOWN PROGRAM
        # ----------------------------------------

        if unknown_program:

            weight = self.weights[
                "unknown_program"
            ]

            score += weight

            reasons.append(
                f"Unknown/suspicious program "
                f"(+{weight})"
            )

        # Never allow score above 100.
        score = min(score, 100)

        level = self._get_level(score)

        return ThreatScore(
            score=score,
            level=level,
            reasons=reasons,
        )

    def _get_level(self, score):

        if score < self.normal_max:

            return "NORMAL"

        if score < self.warning_max:

            return "WARNING"

        return "CRITICAL"