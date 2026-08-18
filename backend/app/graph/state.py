from typing import TypedDict


class GraphState(TypedDict):

    # Original security log
    log: object

    # Threat scoring
    score: int
    score_breakdown: dict

    # IOC intelligence
    malicious_ip: bool
    abuse_score: int
    country: str
    isp: str
    intelligence_source: str

    # Risk classification
    severity: str

    # Attack analysis
    attack: str
    confidence: float

    # Deterministic recommendation
    recommendation: str

    # LLM-generated explanation
    llm_explanation: str