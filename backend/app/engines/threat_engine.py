from app.schemas.threat import ThreatLog
from app.schemas.threat_response import ThreatResponse


class ThreatEngine:

    @staticmethod
    def calculate_score(log: ThreatLog) -> int:

        score = 0

        # Failed Login Attempts
        if log.failed_attempts >= 10:
            score += 40

        # Admin Account
        if log.username.lower() == "admin":
            score += 20

        # Unknown Country
        if log.country.lower() == "unknown":
            score += 20

        # Server Device
        if "server" in log.device.lower():
            score += 20

        return min(score, 100)

    @staticmethod
    def calculate_score_breakdown(log: ThreatLog) -> dict:

        breakdown = {}

        # Failed Login Attempts
        if log.failed_attempts >= 10:
            breakdown["failed_login_attempts"] = 40

        # Admin Account
        if log.username.lower() == "admin":
            breakdown["admin_account"] = 20

        # Unknown Country
        if log.country.lower() == "unknown":
            breakdown["unknown_country"] = 20

        # Server Device
        if "server" in log.device.lower():
            breakdown["server_device"] = 20

        return breakdown

    @staticmethod
    def classify_severity(score: int) -> str:

        if score >= 80:
            return "CRITICAL"

        elif score >= 60:
            return "HIGH"

        elif score >= 30:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def detect_attack(log: ThreatLog) -> str:
        """
        Identify the most likely attack type using
        observable characteristics from the security log.
        """

        event = log.event.lower()
        username = log.username.lower()
        device = log.device.lower()

        # --------------------------------------------------
        # Brute Force
        # --------------------------------------------------

        if (
            log.failed_attempts >= 5
            or "failed login" in event
            or "multiple login" in event
            or "brute force" in event
        ):
            return "Brute Force"

        # --------------------------------------------------
        # Network Reconnaissance
        # --------------------------------------------------

        if (
            "port scan" in event
            or "port scanning" in event
            or "scan detected" in event
            or "reconnaissance" in event
        ):
            return "Network Reconnaissance"

        # --------------------------------------------------
        # Suspicious Administrative Access
        # --------------------------------------------------

        if (
            username == "admin"
            and (
                "login" in event
                or "access" in event
                or "authentication" in event
            )
        ):
            return "Suspicious Administrative Access"

        # --------------------------------------------------
        # Suspicious Server Activity
        # --------------------------------------------------

        if (
            "server" in device
            and (
                "unauthorized" in event
                or "suspicious" in event
                or "access" in event
            )
        ):
            return "Suspicious Server Activity"

        # --------------------------------------------------
        # Generic fallback
        # --------------------------------------------------

        return "Suspicious Activity"

    @staticmethod
    def calculate_confidence(log: ThreatLog, attack: str) -> float:
        """
        Calculate a rule-based confidence score.

        This represents how strongly the observed log
        characteristics support the detected attack type.
        """

        confidence = 0.50

        if attack == "Brute Force":

            if log.failed_attempts >= 10:
                confidence += 0.35

            elif log.failed_attempts >= 5:
                confidence += 0.25

            if "failed login" in log.event.lower():
                confidence += 0.10

        elif attack == "Network Reconnaissance":

            if "port scan" in log.event.lower():
                confidence += 0.35

            elif "scan" in log.event.lower():
                confidence += 0.25

        elif attack == "Suspicious Administrative Access":

            if log.username.lower() == "admin":
                confidence += 0.25

            if "login" in log.event.lower():
                confidence += 0.10

        elif attack == "Suspicious Server Activity":

            if "server" in log.device.lower():
                confidence += 0.25

            if "suspicious" in log.event.lower():
                confidence += 0.15

        else:
            confidence += 0.10

        return min(round(confidence, 2), 0.99)

    @staticmethod
    def generate_recommendation(severity: str) -> str:

        recommendations = {
            "LOW": "Monitor the activity.",
            "MEDIUM": "Investigate suspicious activity.",
            "HIGH": "Block IP and notify SOC.",
            "CRITICAL": "Immediately isolate affected system."
        }

        return recommendations[severity]

    @classmethod
    def analyze(cls, log: ThreatLog) -> ThreatResponse:

        score = cls.calculate_score(log)

        severity = cls.classify_severity(score)

        attack = cls.detect_attack(log)

        confidence = cls.calculate_confidence(
            log,
            attack
        )

        recommendation = cls.generate_recommendation(
            severity
        )

        return ThreatResponse(
            score=score,
            severity=severity,
            attack=attack,
            confidence=confidence,
            recommendation=recommendation
        )