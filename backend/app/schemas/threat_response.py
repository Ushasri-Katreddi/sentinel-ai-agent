from typing import Dict

from pydantic import BaseModel


class ThreatResponse(BaseModel):

    score: int
    severity: str
    attack: str
    confidence: float
    recommendation: str

    score_breakdown: Dict[str, int]

    malicious_ip: bool
    abuse_score: int
    country: str
    isp: str
    intelligence_source: str