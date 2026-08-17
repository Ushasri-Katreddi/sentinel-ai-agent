from app.engines.threat_engine import ThreatEngine


class RecommendationAgent:

    @staticmethod
    def recommend(severity: str):
        return ThreatEngine.generate_recommendation(severity)