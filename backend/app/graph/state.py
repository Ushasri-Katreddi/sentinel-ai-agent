from typing import TypedDict


class GraphState(TypedDict):

    log: object

    score: int

    score_breakdown: dict

    malicious_ip: bool
    abuse_score: int
    country: str
    isp: str
    intelligence_source: str

    severity: str
    attack: str
    confidence: float
    recommendation: str