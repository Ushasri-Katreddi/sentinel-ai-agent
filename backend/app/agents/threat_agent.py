from app.schemas.threat import ThreatLog
from app.engines.threat_engine import ThreatEngine


class ThreatAgent:

    @staticmethod
    def analyze(log: ThreatLog):
        return ThreatEngine.calculate_score(log)