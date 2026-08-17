from app.agents.recommendation_agent import RecommendationAgent


severity = "HIGH"

recommendation = RecommendationAgent.recommend(severity)

print("Recommendation:")
print(recommendation)