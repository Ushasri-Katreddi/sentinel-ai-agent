from app.agents.threat_agent import ThreatAgent
from app.agents.risk_agent import RiskAgent
from app.agents.recommendation_agent import RecommendationAgent
from app.agents.supervisor import SupervisorAgent

from app.engines.threat_engine import ThreatEngine

from app.tools.ioc_lookup import IOCLookup

from app.services.llm_service import LLMService
from app.services.notification_service import NotificationService

from app.utils.logger import logger


# ============================================================
# SUPERVISOR NODE
# ============================================================
#
# The Supervisor is the entry point of the Sentinel workflow.
#
# Its responsibility is to decide which analysis path should
# be followed.
#
# Possible decisions:
#
#     FULL_ANALYSIS
#         Threat -> IOC -> Risk -> Recommendation
#
#     THREAT_ONLY
#         Threat -> Risk -> Recommendation
#
# The Supervisor itself does not calculate the threat score.
# ============================================================

def supervisor_node(state):

    logger.info(
        "SUPERVISOR NODE | Starting Sentinel workflow"
    )

    # Ask the SupervisorAgent to decide which workflow
    # should be executed.
    state = SupervisorAgent.start(state)

    # --------------------------------------------------------
    # Initialize IOC fields with safe default values.
    #
    # If the Supervisor chooses THREAT_ONLY, the IOC node
    # will be skipped.
    #
    # These defaults make sure downstream nodes still have
    # valid values to work with.
    # --------------------------------------------------------

    state.setdefault(
        "malicious_ip",
        False
    )

    state.setdefault(
        "abuse_score",
        0
    )

    # If IOC is skipped, use the country from the original log.
    state.setdefault(
        "country",
        state["log"].country
    )

    state.setdefault(
        "isp",
        "Not checked"
    )

    state.setdefault(
        "intelligence_source",
        "NOT_CHECKED"
    )

    logger.info(
        f"SUPERVISOR NODE | "
        f"Workflow decision={state['next_step']}"
    )

    return state


# ============================================================
# THREAT NODE
# ============================================================
#
# Performs the initial threat analysis.
#
# CURRENTLY:
#     ThreatAgent -> rule-based ThreatEngine
#
# LATER:
#     ThreatAgent -> trained ML model
#
# We keep this node separate so that the scoring mechanism
# can later be replaced without redesigning LangGraph.
# ============================================================

def threat_node(state):

    logger.info(
        "THREAT NODE | Starting threat analysis"
    )

    log = state["log"]

    # Calculate the base threat score.
    score = ThreatAgent.analyze(log)

    # Calculate an explainable breakdown of the score.
    breakdown = ThreatEngine.calculate_score_breakdown(
        log
    )

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
#
# Performs IP reputation / threat intelligence lookup.
#
# This node runs only when the Supervisor selects:
#
#     FULL_ANALYSIS
#
# This prevents unnecessary IOC lookups for ordinary events.
# ============================================================

def ioc_node(state):

    ip = state["log"].source_ip

    logger.info(
        f"IOC NODE | Checking IP reputation | IP={ip}"
    )

    # Query the IOC intelligence system.
    result = IOCLookup.lookup(ip)

    # --------------------------------------------------------
    # Store IOC intelligence in GraphState.
    # --------------------------------------------------------

    state["malicious_ip"] = result["is_malicious"]

    state["abuse_score"] = result["abuse_score"]

    state["country"] = result["country"]

    state["isp"] = result["isp"]

    state["intelligence_source"] = (
        result["intelligence_source"]
    )

    logger.info(
        f"IOC NODE | Intelligence source used="
        f"{result['intelligence_source']} | "
        f"IP={ip} | "
        f"malicious={result['is_malicious']} | "
        f"abuse_score={result['abuse_score']}"
    )

    # --------------------------------------------------------
    # Add IOC intelligence to the threat score.
    #
    # CURRENT PoC:
    #
    #     malicious IP -> +40
    #
    # Later, ML probability and IOC intelligence can be
    # combined in a more sophisticated scoring system.
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
#
# Converts the final threat score into a severity level.
#
# Example:
#
#     80+ -> CRITICAL
#     60+ -> HIGH
#     30+ -> MEDIUM
#     <30 -> LOW
# ============================================================

def risk_node(state):

    logger.info(
        f"RISK NODE | Classifying severity | "
        f"score={state['score']}"
    )

    # Ask RiskAgent to classify the final score.
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
#
# This node performs three major responsibilities:
#
#     1. Generate deterministic recommendation
#     2. Generate LLM explanation when needed
#     3. Send the security alert email
#
# IMPORTANT:
#
# Phi-4-mini does NOT determine:
#
#     - threat score
#     - severity
#     - recommendation
#
# Those decisions come from our deterministic security logic.
#
# Phi-4-mini only explains the already-determined result.
# ============================================================

def recommendation_node(state):

    logger.info(
        f"RECOMMENDATION NODE | "
        f"Generating recommendation | "
        f"severity={state['severity']}"
    )

    # ========================================================
    # 1. GENERATE DETERMINISTIC RECOMMENDATION
    # ========================================================
    #
    # RecommendationAgent decides what action should be taken
    # based on the severity.
    #
    # Example:
    #
    # CRITICAL
    #     -> Immediately isolate affected system.
    #
    # LOW
    #     -> Monitor the activity.
    # ========================================================

    recommendation = RecommendationAgent.recommend(
        state["severity"]
    )

    state["recommendation"] = recommendation

    # ========================================================
    # 2. CURRENT ATTACK CLASSIFICATION
    # ========================================================
    #
    # This is still a PoC value.
    #
    # Later, the ML layer can determine the attack type.
    # ========================================================

    state["attack"] = "Brute Force"

    state["confidence"] = 0.85

    logger.info(
        f"RECOMMENDATION NODE | "
        f"Recommendation={recommendation}"
    )


    # ========================================================
    # 3. SELECTIVE LLM INVOCATION
    # ========================================================
    #
    # THIS IS THE NEW OPTIMIZATION.
    #
    # We do not need Phi-4-mini for every event.
    #
    # LOW-risk events already have a straightforward
    # deterministic result:
    #
    #     LOW
    #       ->
    #     Monitor the activity.
    #
    # Therefore we skip LLM inference for LOW.
    #
    # MEDIUM / HIGH / CRITICAL events receive an AI-generated
    # explanation because these incidents are more valuable
    # for a SOC analyst to understand.
    # ========================================================

    severity = state["severity"]

    if severity == "LOW":

        logger.info(
            "RECOMMENDATION NODE | "
            "LOW severity detected | "
            "Skipping LLM explanation"
        )

        # Store a simple explanation so that:
        #
        # 1. GraphState remains complete
        # 2. NotificationService can still send the email
        #
        state["llm_explanation"] = (
            "The security event was classified as LOW risk "
            "based on the available security indicators. "
            "No immediate action is required beyond monitoring."
        )

    else:

        logger.info(
            "RECOMMENDATION NODE | "
            f"{severity} severity detected | "
            "Generating LLM security explanation"
        )

        # ----------------------------------------------------
        # Create the LLM service.
        # ----------------------------------------------------

        llm_service = LLMService()

        ip = state["log"].source_ip

        # ----------------------------------------------------
        # Ask Phi-4-mini to explain the security incident.
        #
        # The LLM receives facts already determined by Sentinel.
        # It does not make the security decision itself.
        # ----------------------------------------------------

        llm_explanation = (
            llm_service.generate_security_explanation(

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

                intelligence_source=state[
                    "intelligence_source"
                ],
            )
        )

        # ----------------------------------------------------
        # Store the generated explanation in GraphState.
        # ----------------------------------------------------

        state["llm_explanation"] = llm_explanation

        logger.info(
            "RECOMMENDATION NODE | "
            "LLM explanation generated successfully"
        )


    # ========================================================
    # 4. SEND SECURITY ALERT EMAIL
    # ========================================================
    #
    # We send the alert regardless of whether the LLM was
    # invoked.
    #
    # This means:
    #
    # LOW:
    #     Deterministic explanation -> Email
    #
    # MEDIUM/HIGH/CRITICAL:
    #     Phi-4-mini explanation -> Email
    #
    # ========================================================

    notification_service = NotificationService()

    ip = state["log"].source_ip

    notification_result = (
        notification_service.send_alert(

            # Source IP involved in the event.
            ip=ip,

            # IOC information.
            malicious_ip=state["malicious_ip"],

            abuse_score=state["abuse_score"],

            # Geographic information.
            country=state["country"],

            # ISP information.
            isp=state["isp"],

            # Intelligence source.
            intelligence_source=state[
                "intelligence_source"
            ],

            # Final Sentinel score.
            score=state["score"],

            # Risk classification.
            severity=state["severity"],

            # Attack classification.
            attack=state["attack"],

            # Confidence.
            confidence=state["confidence"],

            # Recommended action.
            recommendation=state[
                "recommendation"
            ],

            # Either Phi-4-mini explanation or the
            # deterministic LOW-risk explanation.
            llm_explanation=state[
                "llm_explanation"
            ],
        )
    )

    # --------------------------------------------------------
    # Log the Brevo message ID.
    #
    # This confirms that the email request was accepted
    # by Brevo.
    # --------------------------------------------------------

    logger.info(
        f"RECOMMENDATION NODE | "
        f"Security alert sent | "
        f"message_id="
        f"{notification_result.get('messageId')}"
    )

    return state