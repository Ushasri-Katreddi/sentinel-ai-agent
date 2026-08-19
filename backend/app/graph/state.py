from typing import TypedDict


class GraphState(TypedDict):

    # ============================================================
    # ORIGINAL SECURITY LOG
    # ============================================================
    # The raw security event received by Sentinel AI.
    # ============================================================

    log: object


    # ============================================================
    # SUPERVISOR DECISION
    # ============================================================
    #
    # The Supervisor decides which workflow should be followed.
    #
    # FULL_ANALYSIS:
    #     Threat -> IOC -> Risk -> Recommendation
    #
    # THREAT_ONLY:
    #     Threat -> Risk -> Recommendation
    #
    # ============================================================

    next_step: str


    # ============================================================
    # THREAT SCORING
    # ============================================================

    score: int

    # Explains how the score was calculated.
    #
    # Example:
    #
    # {
    #     "failed_login_attempts": 40,
    #     "admin_account": 20
    # }
    #

    score_breakdown: dict


    # ============================================================
    # IOC / THREAT INTELLIGENCE
    # ============================================================

    malicious_ip: bool

    abuse_score: int

    country: str

    isp: str

    intelligence_source: str


    # ============================================================
    # RISK CLASSIFICATION
    # ============================================================

    severity: str


    # ============================================================
    # ATTACK ANALYSIS
    # ============================================================

    attack: str

    confidence: float


    # ============================================================
    # SECURITY RECOMMENDATION
    # ============================================================

    recommendation: str


    # ============================================================
    # LLM-GENERATED EXPLANATION
    # ============================================================
    #
    # Phi-4-mini explains the security decision in
    # human-readable language.
    #
    # The LLM does NOT determine the security score.
    #
    # ============================================================

    llm_explanation: str