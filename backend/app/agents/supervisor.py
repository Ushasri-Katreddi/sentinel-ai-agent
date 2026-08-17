from app.agents.threat_agent import ThreatAgent
from app.agents.risk_agent import RiskAgent
from app.agents.recommendation_agent import RecommendationAgent

from app.schemas.threat import ThreatLog
from app.schemas.threat_response import ThreatResponse


class SupervisorAgent:

    @staticmethod
    def analyze(log: ThreatLog) -> ThreatResponse:

        score = ThreatAgent.analyze(log)

        severity = RiskAgent.classify(score)

        recommendation = RecommendationAgent.recommend(severity)

        return ThreatResponse(
            score=score,
            severity=severity,
            attack="Brute Force",
            confidence=0.95,
            recommendation=recommendation
        )