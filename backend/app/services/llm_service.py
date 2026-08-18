import os

import requests
from dotenv import load_dotenv


load_dotenv()


class LLMService:

    def __init__(self):

        self.base_url = os.getenv(
            "OLLAMA_BASE_URL",
            "http://localhost:11434"
        )

        self.model = os.getenv(
            "OLLAMA_MODEL",
            "phi4-mini"
        )

        self.url = f"{self.base_url}/api/generate"

    def generate_security_explanation(
        self,
        ip: str,
        score: int,
        severity: str,
        attack: str,
        confidence: float,
        malicious_ip: bool,
        abuse_score: int,
        country: str,
        isp: str,
        intelligence_source: str,
        recommendation: str,
    ) -> str:

        prompt = f"""
You are a cybersecurity SOC assistant.

Security incident:
IP: {ip}
Threat score: {score}
Severity: {severity}
Attack: {attack}
Confidence: {confidence}
Malicious IP: {malicious_ip}
Abuse score: {abuse_score}
Country: {country}
ISP: {isp}
Intelligence source: {intelligence_source}
Recommended action: {recommendation}

Write a concise SOC explanation.

Rules:
1. Explain why the severity is {severity}.
2. Mention the strongest evidence.
3. Explain the recommended action.
4. Do not change the severity.
5. Do not invent facts.
6. Do not recommend a different action.
7. Maximum 60 words.
"""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,

            # Keep the model loaded after the request.
            "keep_alive": "10m",

            # Reduce generation time.
            "options": {
                "temperature": 0.1,
                "num_predict": 80,
                "num_ctx": 2048,
            },
        }

        response = requests.post(
            self.url,
            json=payload,
            timeout=180,
        )

        response.raise_for_status()

        result = response.json()

        explanation = result.get(
            "response",
            ""
        ).strip()

        if not explanation:
            return "Unable to generate security explanation."

        return explanation
    