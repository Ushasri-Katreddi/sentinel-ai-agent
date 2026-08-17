from app.engines.threat_engine import ThreatEngine


class RiskAgent:

    @staticmethod
    def classify(score: int):
        return ThreatEngine.classify_severity(score)