import json
from pathlib import Path

from app.tools.abuseipdb import check_ip_reputation
from app.utils.logger import logger


class IOCLookup:

    @staticmethod
    def lookup(ip: str):

        logger.info(
            f"IOC LOOKUP | Starting lookup for IP={ip}"
        )

        # Project root:
        # sentinel-ai-agent/
        BASE_DIR = Path(__file__).resolve().parents[3]

        dataset_path = (
            BASE_DIR
            / "datasets"
            / "malicious_ips.json"
        )

        logger.info(
            f"IOC LOOKUP | Local dataset path={dataset_path}"
        )

        # ==================================================
        # SOURCE 1: LOCAL IOC DATASET
        # ==================================================

        try:

            with open(
                dataset_path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            malicious_ips = data.get(
                "malicious_ips",
                []
            )

            if ip in malicious_ips:

                logger.warning(
                    f"IOC LOOKUP | Intelligence source="
                    f"LOCAL_IOC_DATASET | "
                    f"IP={ip} | "
                    f"malicious=True"
                )

                return {
                    "is_malicious": True,
                    "abuse_score": 100,
                    "country": "Unknown",
                    "isp": "Local IOC Dataset",
                    "intelligence_source": "LOCAL_IOC_DATASET"
                }

            logger.info(
                f"IOC LOOKUP | Intelligence source="
                f"LOCAL_IOC_DATASET | "
                f"IP={ip} | "
                f"result=NOT_FOUND"
            )

        except Exception as e:

            logger.error(
                f"IOC LOOKUP | Local IOC dataset unavailable | "
                f"error={e}"
            )

        # ==================================================
        # SOURCE 2: ABUSEIPDB
        # ==================================================

        logger.info(
            f"IOC LOOKUP | Intelligence source="
            f"ABUSEIPDB | "
            f"IP={ip} | "
            f"action=API_CALL"
        )

        result = check_ip_reputation(ip)

        # AbuseIPDB function returns its own source information
        result["intelligence_source"] = "ABUSEIPDB"

        logger.info(
            f"IOC LOOKUP | Intelligence source="
            f"ABUSEIPDB | "
            f"IP={ip} | "
            f"malicious={result['is_malicious']} | "
            f"abuse_score={result['abuse_score']} | "
            f"country={result['country']} | "
            f"isp={result['isp']}"
        )

        logger.info(
            f"IOC LOOKUP | Final intelligence source="
            f"{result['intelligence_source']} | "
            f"IP={ip}"
        )

        return result