from app.utils.logger import logger


class SupervisorAgent:
    """
    SupervisorAgent is responsible for deciding which
    analysis path Sentinel AI should follow.

    IMPORTANT:

    The Supervisor does NOT calculate the threat score.

    The Supervisor does NOT determine severity.

    The Supervisor does NOT generate recommendations.

    Those responsibilities belong to the specialized agents.

    The Supervisor only decides:

        "Does this event require full threat intelligence
         analysis, or can we perform a lighter analysis?"
    """

    @staticmethod
    def decide(log) -> str:

        # --------------------------------------------------------
        # Normalize event information.
        #
        # We convert strings to lowercase so that:
        #
        # "FAILED LOGIN"
        # "Failed Login"
        # "failed login"
        #
        # are treated the same way.
        # --------------------------------------------------------

        event = log.event.lower()
        username = log.username.lower()
        country = log.country.lower()
        device = log.device.lower()

        # --------------------------------------------------------
        # Rule 1:
        #
        # Multiple failed login attempts are suspicious.
        #
        # Five or more failed attempts will trigger
        # full analysis including IOC lookup.
        # --------------------------------------------------------

        if log.failed_attempts >= 5:

            logger.info(
                "SUPERVISOR | Suspicious failed-login activity detected"
            )

            return "FULL_ANALYSIS"

        # --------------------------------------------------------
        # Rule 2:
        #
        # Certain security-related event keywords indicate
        # suspicious activity.
        # --------------------------------------------------------

        suspicious_keywords = [
            "failed login",
            "brute force",
            "unauthorized",
            "intrusion",
            "attack",
            "malware",
            "suspicious",
            "port scan",
            "credential",
        ]

        if any(
            keyword in event
            for keyword in suspicious_keywords
        ):

            logger.info(
                "SUPERVISOR | Suspicious security event detected"
            )

            return "FULL_ANALYSIS"

        # --------------------------------------------------------
        # Rule 3:
        #
        # Admin activity combined with an unusual country
        # deserves additional investigation.
        # --------------------------------------------------------

        if (
            username == "admin"
            and country == "unknown"
        ):

            logger.info(
                "SUPERVISOR | Admin activity from unknown country detected"
            )

            return "FULL_ANALYSIS"

        # --------------------------------------------------------
        # Rule 4:
        #
        # Server + unusual country is also worth investigating.
        # --------------------------------------------------------

        if (
            "server" in device
            and country == "unknown"
        ):

            logger.info(
                "SUPERVISOR | Server activity from unknown country detected"
            )

            return "FULL_ANALYSIS"

        # --------------------------------------------------------
        # Default path:
        #
        # Nothing strongly suspicious was detected.
        #
        # We can avoid the IOC lookup and perform a lighter
        # threat analysis.
        # --------------------------------------------------------

        logger.info(
            "SUPERVISOR | No strong suspicious indicators detected"
        )

        return "THREAT_ONLY"

    @staticmethod
    def start(state):

        logger.info(
            "SUPERVISOR | Starting Sentinel security analysis"
        )

        # --------------------------------------------------------
        # Ask the Supervisor to decide the workflow.
        # --------------------------------------------------------

        decision = SupervisorAgent.decide(
            state["log"]
        )

        # --------------------------------------------------------
        # Store the decision in GraphState.
        #
        # LangGraph will use this value to determine which
        # node should execute next.
        # --------------------------------------------------------

        state["next_step"] = decision

        logger.info(
            f"SUPERVISOR | Workflow decision = {decision}"
        )

        return state