import os
import requests
from dotenv import load_dotenv

from app.utils.logger import logger


load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_ip_reputation(ip: str):

    logger.info(
        f"ABUSEIPDB | API request started | IP={ip}"
    )

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        logger.info(
            f"ABUSEIPDB | API response received | "
            f"status={response.status_code} | "
            f"IP={ip}"
        )

        response.raise_for_status()

        data = response.json()["data"]

        result = {
            "is_malicious": data["abuseConfidenceScore"] >= 50,
            "abuse_score": data["abuseConfidenceScore"],
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }

        logger.info(
            f"ABUSEIPDB | Parsed response | "
            f"IP={ip} | "
            f"abuse_score={result['abuse_score']} | "
            f"malicious={result['is_malicious']}"
        )

        return result

    except Exception as e:

        logger.error(
            f"ABUSEIPDB | API request failed | "
            f"IP={ip} | "
            f"error={e}"
        )

        return {
            "is_malicious": False,
            "abuse_score": 0,
            "country": "Unknown",
            "isp": "Unknown"
        }