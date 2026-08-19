from langgraph.graph import StateGraph, START, END

from app.graph.state import GraphState

from app.graph.nodes import (
    supervisor_node,
    threat_node,
    ioc_node,
    risk_node,
    recommendation_node,
)


# ============================================================
# CREATE THE LANGGRAPH STATE GRAPH
# ============================================================
#
# GraphState defines the information that flows between
# our nodes.
#
# ============================================================

builder = StateGraph(GraphState)


# ============================================================
# ADD NODES
# ============================================================
#
# Each node represents one responsibility in Sentinel.
#
# ============================================================

builder.add_node(
    "Supervisor",
    supervisor_node
)

builder.add_node(
    "Threat",
    threat_node
)

builder.add_node(
    "IOC",
    ioc_node
)

builder.add_node(
    "Risk",
    risk_node
)

builder.add_node(
    "Recommendation",
    recommendation_node
)


# ============================================================
# START → SUPERVISOR
# ============================================================
#
# Every incoming security event starts at the Supervisor.
#
# ============================================================

builder.add_edge(
    START,
    "Supervisor"
)


# ============================================================
# SUPERVISOR → CONDITIONAL ROUTING
# ============================================================
#
# Instead of always doing:
#
#     Supervisor → Threat → IOC → Risk
#
# the Supervisor now chooses the workflow.
#
# ============================================================

def supervisor_router(state):
    """
    Reads the decision made by SupervisorAgent and tells
    LangGraph which node should execute next.
    """

    decision = state["next_step"]

    # --------------------------------------------------------
    # FULL_ANALYSIS:
    #
    # Suspicious event → perform Threat + IOC analysis.
    # --------------------------------------------------------

    if decision == "FULL_ANALYSIS":

        return "Threat"

    # --------------------------------------------------------
    # THREAT_ONLY:
    #
    # Normal event → perform Threat analysis but skip IOC.
    # --------------------------------------------------------

    if decision == "THREAT_ONLY":

        return "Threat"

    # --------------------------------------------------------
    # Safety fallback.
    #
    # If an unexpected value somehow appears, perform the
    # complete analysis rather than silently skipping security
    # checks.
    # --------------------------------------------------------

    return "Threat"


builder.add_conditional_edges(
    "Supervisor",
    supervisor_router,
    {
        "Threat": "Threat",
    }
)


# ============================================================
# THREAT → CONDITIONAL IOC / RISK
# ============================================================
#
# Threat analysis always happens.
#
# After Threat:
#
# FULL_ANALYSIS
#       ↓
#     IOC
#
# THREAT_ONLY
#       ↓
#     Risk
#
# ============================================================

def threat_router(state):
    """
    Determines whether IOC analysis is required after the
    Threat node has completed.
    """

    if state["next_step"] == "FULL_ANALYSIS":

        return "IOC"

    return "Risk"


builder.add_conditional_edges(
    "Threat",
    threat_router,
    {
        "IOC": "IOC",
        "Risk": "Risk",
    }
)


# ============================================================
# IOC → RISK
# ============================================================
#
# Once IOC analysis is completed, the combined security
# evidence goes to RiskAgent.
#
# ============================================================

builder.add_edge(
    "IOC",
    "Risk"
)


# ============================================================
# RISK → RECOMMENDATION
# ============================================================
#
# RiskAgent classifies the final score.
#
# ============================================================

builder.add_edge(
    "Risk",
    "Recommendation"
)


# ============================================================
# RECOMMENDATION → END
# ============================================================
#
# Recommendation node also:
#
#     1. Generates recommendation
#     2. Generates Phi-4-mini explanation
#     3. Sends email
#
# ============================================================

builder.add_edge(
    "Recommendation",
    END
)


# ============================================================
# COMPILE GRAPH
# ============================================================
#
# After compilation, "graph" is the executable LangGraph
# workflow used by ThreatService.
#
# ============================================================

graph = builder.compile()