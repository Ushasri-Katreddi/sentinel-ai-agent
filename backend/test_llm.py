from app.services.llm_service import LLMService


llm_service = LLMService()


explanation = llm_service.generate_security_explanation(
    ip="185.220.101.1",
    score=80,
    severity="CRITICAL",
    attack="Brute Force",
    confidence=0.85,
    malicious_ip=True,
    abuse_score=100,
    country="Unknown",
    isp="Local IOC Dataset",
    intelligence_source="LOCAL_IOC_DATASET",
    recommendation="Immediately isolate affected system.",
)


print("\nLLM SECURITY EXPLANATION:")
print(explanation)