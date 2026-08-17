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

        recommendation = cls.generate_recommendation(severity)

        return ThreatResponse(
            score=score,
            severity=severity,
            attack="Brute Force",
            confidence=0.95,
            recommendation=recommendation
        )