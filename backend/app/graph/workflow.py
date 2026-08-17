from langgraph.graph import StateGraph, START, END

from app.graph.state import GraphState
from app.graph.nodes import (
    threat_node,
    ioc_node,
    risk_node,
    recommendation_node,
)

# Create the graph
builder = StateGraph(GraphState)

# Add nodes
builder.add_node("Threat", threat_node)
builder.add_node("IOC", ioc_node)
builder.add_node("Risk", risk_node)
builder.add_node("Recommendation", recommendation_node)

# Define workflow
builder.add_edge(START, "Threat")
builder.add_edge("Threat", "IOC")
builder.add_edge("IOC", "Risk")
builder.add_edge("Risk", "Recommendation")
builder.add_edge("Recommendation", END)

# Compile the graph
graph = builder.compile()