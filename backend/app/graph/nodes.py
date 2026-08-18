from app.agents.threat_agent import ThreatAgent
from app.agents.risk_agent import RiskAgent
from app.agents.recommendation_agent import RecommendationAgent

from app.engines.threat_engine import ThreatEngine

from app.tools.ioc_lookup import IOCLookup

from app.services.llm_service import LLMService
from app.services.notification_service import NotificationService

from app.utils.logger import logger


# ============================================================
# THREAT NODE
# ============================================================

def threat_node(state):

    logger.info(
        "THREAT NODE | Starting threat analysis"
    )

    log = state["log"]

    # --------------------------------------------------------
    # Calculate base threat score
    # --------------------------------------------------------

    score = ThreatAgent.analyze(log)

    # --------------------------------------------------------
    # Calculate explainable score breakdown
    # --------------------------------------------------------

    breakdown = ThreatEngine.calculate_score_breakdown(log)

    state["score"] = score
    state["score_breakdown"] = breakdown

    logger.info(
        f"THREAT NODE | Threat score calculated = {score}"
    )

    logger.info(
        f"THREAT NODE | Score breakdown = {breakdown}"
    )

    return state


# ============================================================
# IOC NODE
# ============================================================

def ioc_node(state):

    ip = state["log"].source_ip

    logger.info(
        f"IOC NODE | Checking IP reputation | IP={ip}"
    )

    # --------------------------------------------------------
    # Lookup IP reputation
    # --------------------------------------------------------

    result = IOCLookup.lookup(ip)

    # --------------------------------------------------------
    # Store IOC intelligence
    # --------------------------------------------------------

    state["malicious_ip"] = result["is_malicious"]
    state["abuse_score"] = result["abuse_score"]
    state["country"] = result["country"]
    state["isp"] = result["isp"]
    state["intelligence_source"] = result["intelligence_source"]

    logger.info(
        f"IOC NODE | Intelligence source used="
        f"{result['intelligence_source']} | "
        f"IP={ip} | "
        f"malicious={result['is_malicious']} | "
        f"abuse_score={result['abuse_score']}"
    )

    # --------------------------------------------------------
    # Add IOC contribution to threat score
    # --------------------------------------------------------

    if result["is_malicious"]:

        state["score"] += 40

        state["score_breakdown"]["ioc_reputation"] = 40

        logger.warning(
            f"IOC NODE | MALICIOUS IP DETECTED | "
            f"IP={ip} | "
            f"Source={result['intelligence_source']} | "
            f"Score increased by 40 | "
            f"New score={state['score']}"
        )

    else:

        state["score_breakdown"]["ioc_reputation"] = 0

        logger.info(
            f"IOC NODE | IP not malicious | "
            f"IP={ip} | "
            f"Source={result['intelligence_source']}"
        )

    logger.info(
        f"IOC NODE | Final IOC analysis | "
        f"IP={ip} | "
        f"Source={result['intelligence_source']} | "
        f"malicious={result['is_malicious']} | "
        f"final_score={state['score']}"
    )

    logger.info(
        f"IOC NODE | Final score breakdown="
        f"{state['score_breakdown']}"
    )

    return state


# ============================================================
# RISK NODE
# ============================================================

def risk_node(state):

    logger.info(
        f"RISK NODE | Classifying severity | "
        f"score={state['score']}"
    )

    severity = RiskAgent.classify(
        state["score"]
    )

    state["severity"] = severity

    logger.info(
        f"RISK NODE | Severity={severity}"
    )

    return state


# ============================================================
# RECOMMENDATION NODE
# ============================================================

def recommendation_node(state):

    logger.info(
        f"RECOMMENDATION NODE | Generating recommendation | "
        f"severity={state['severity']}"
    )

    # --------------------------------------------------------
    # 1. Generate deterministic security recommendation
    # --------------------------------------------------------

    recommendation = RecommendationAgent.recommend(
        state["severity"]
    )

    state["recommendation"] = recommendation

    # --------------------------------------------------------
    # 2. Attack classification
    #
    # Currently this is our PoC classification.
    # Later this can be replaced by an ML-based classifier.
    # --------------------------------------------------------

    state["attack"] = "Brute Force"

    state["confidence"] = 0.85

    logger.info(
        f"RECOMMENDATION NODE | "
        f"Recommendation={recommendation}"
    )

    # --------------------------------------------------------
    # 3. Generate LLM security explanation
    #
    # IMPORTANT:
    # The LLM does NOT decide the risk.
    #
    # ThreatAgent + IOC + RiskAgent determine the security
    # result.
    #
    # Phi-4-mini only explains that result in human-readable
    # language.
    # --------------------------------------------------------

    logger.info(
        "RECOMMENDATION NODE | Generating LLM security explanation"
    )

    ip = state["log"].source_ip

    llm_service = LLMService()

    llm_explanation = llm_service.generate_security_explanation(
        ip=ip,
        score=state["score"],
        severity=state["severity"],
        attack=state["attack"],
        confidence=state["confidence"],
        recommendation=state["recommendation"],
        malicious_ip=state["malicious_ip"],
        abuse_score=state["abuse_score"],
        country=state["country"],
        isp=state["isp"],
        intelligence_source=state["intelligence_source"],
    )

    # --------------------------------------------------------
    # VERY IMPORTANT
    # Store LLM result in GraphState BEFORE using it.
    # This fixes the KeyError you received.
    # --------------------------------------------------------

    state["llm_explanation"] = llm_explanation

    logger.info(
        "RECOMMENDATION NODE | LLM explanation generated successfully"
    )

    # --------------------------------------------------------
    # 4. Send security alert email
    # --------------------------------------------------------

    notification_service = NotificationService()

    notification_result = notification_service.send_alert(

        ip=ip,

        malicious_ip=state["malicious_ip"],

        abuse_score=state["abuse_score"],

        country=state["country"],

        isp=state["isp"],

        intelligence_source=state["intelligence_source"],

        score=state["score"],

        severity=state["severity"],

        attack=state["attack"],

        confidence=state["confidence"],

        recommendation=state["recommendation"],

        llm_explanation=state["llm_explanation"],
    )

    logger.info(
        f"RECOMMENDATION NODE | Security alert sent | "
        f"message_id={notification_result.get('messageId')}"
    )

    return state