import os

import requests
from dotenv import load_dotenv


load_dotenv()


class NotificationService:
    """
    Handles email notifications for Sentinel AI.

    Uses Brevo's Transactional Email API
    to send security alerts.
    """

    def __init__(self):
        self.api_key = os.getenv("BREVO_API_KEY")
        self.sender_email = os.getenv("BREVO_SENDER_EMAIL")
        self.sender_name = os.getenv("BREVO_SENDER_NAME")
        self.recipient_email = os.getenv("BREVO_RECIPIENT_EMAIL")

        if not self.api_key:
            raise ValueError("BREVO_API_KEY is not configured")

        if not self.sender_email:
            raise ValueError("BREVO_SENDER_EMAIL is not configured")

        if not self.sender_name:
            raise ValueError("BREVO_SENDER_NAME is not configured")

        if not self.recipient_email:
            raise ValueError("BREVO_RECIPIENT_EMAIL is not configured")

        self.url = "https://api.brevo.com/v3/smtp/email"

    def send_alert(
        self,
        ip: str,
        malicious_ip: bool,
        abuse_score: int,
        country: str,
        isp: str,
        intelligence_source: str,
        score: int,
        severity: str,
        attack: str,
        confidence: float,
        recommendation: str,
    ):

        headers = {
            "accept": "application/json",
            "api-key": self.api_key,
            "content-type": "application/json",
        }

        threat_status = (
            "MALICIOUS"
            if malicious_ip
            else "NOT IDENTIFIED AS MALICIOUS"
        )

        body = (
            "SENTINEL AI SECURITY ALERT\n"
            "\n"
            "================================\n"
            "\n"
            f"IP Address: {ip}\n"
            f"Threat Status: {threat_status}\n"
            f"Risk Score: {score}\n"
            f"Severity: {severity.upper()}\n"
            f"Attack Type: {attack}\n"
            f"Confidence: {confidence * 100:.1f}%\n"
            "\n"
            "--------------------------------\n"
            "THREAT INTELLIGENCE\n"
            "--------------------------------\n"
            f"Abuse Score: {abuse_score}\n"
            f"Country: {country}\n"
            f"ISP: {isp}\n"
            f"Intelligence Source: {intelligence_source}\n"
            "\n"
            "--------------------------------\n"
            "RECOMMENDATION\n"
            "--------------------------------\n"
            f"{recommendation}\n"
            "\n"
            "================================\n"
            "Generated automatically by Sentinel AI."
        )

        payload = {
            "sender": {
                "name": self.sender_name,
                "email": self.sender_email,
            },
            "to": [
                {
                    "email": self.recipient_email,
                }
            ],
            "subject": (
                f"Sentinel AI - "
                f"{severity.upper()} Risk Alert - "
                f"{ip}"
            ),
            "textContent": body,
        }

        response = requests.post(
            self.url,
            headers=headers,
            json=payload,
            timeout=10,
        )

        response.raise_for_status()

        return response.json()