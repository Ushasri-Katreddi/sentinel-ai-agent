import logging

from app.graph.workflow import graph
from app.schemas.threat import ThreatLog
from app.schemas.threat_response import ThreatResponse
from app.database.database import SessionLocal
from app.models.threat_analysis import ThreatAnalysis


logger = logging.getLogger(__name__)


class ThreatService:

    @staticmethod
    def analyze(log: ThreatLog) -> ThreatResponse:

        logger.info(
            "THREAT SERVICE | Starting analysis | IP=%s",
            log.source_ip
        )

        # --------------------------------------------------
        # 1. Run LangGraph workflow
        # --------------------------------------------------

        result = graph.invoke({
            "log": log
        })

        logger.info(
            "THREAT SERVICE | Graph analysis completed | IP=%s | score=%s | severity=%s",
            log.source_ip,
            result["score"],
            result["severity"]
        )

        # --------------------------------------------------
        # 2. Save analysis to PostgreSQL
        # --------------------------------------------------

        db = SessionLocal()

        try:

            analysis = ThreatAnalysis(
                timestamp=log.timestamp,
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                username=log.username,
                event=log.event,
                failed_attempts=log.failed_attempts,
                country=log.country,
                device=log.device,

                # Threat analysis
                score=result["score"],
                severity=result["severity"],
                attack=result["attack"],
                confidence=result["confidence"],
                recommendation=result["recommendation"],

                # Score explanation
                score_breakdown=result.get(
                    "score_breakdown",
                    {}
                ),

                # IOC intelligence
                malicious_ip=result.get(
                    "malicious_ip",
                    False
                ),

                abuse_score=result.get(
                    "abuse_score",
                    0
                ),

                ioc_country=result.get(
                    "country",
                    "Unknown"
                ),

                isp=result.get(
                    "isp",
                    "Unknown"
                ),

                intelligence_source=result.get(
                    "intelligence_source",
                    "UNKNOWN"
                )
            )

            db.add(analysis)
            db.commit()
            db.refresh(analysis)

            logger.info(
                "DATABASE | Threat analysis saved successfully | id=%s | IP=%s | source=%s",
                analysis.id,
                log.source_ip,
                analysis.intelligence_source
            )

        except Exception:

            db.rollback()

            logger.exception(
                "DATABASE | Failed to save threat analysis | IP=%s",
                log.source_ip
            )

            raise

        finally:

            db.close()

        # --------------------------------------------------
        # 3. Return API response
        # --------------------------------------------------

        logger.info(
            "THREAT SERVICE | Returning response | IP=%s",
            log.source_ip
        )

        return ThreatResponse(
            score=result["score"],
            severity=result["severity"],
            attack=result["attack"],
            confidence=result["confidence"],
            recommendation=result["recommendation"],
            score_breakdown=result.get(
                "score_breakdown",
                {}
            ),
            malicious_ip=result.get(
                "malicious_ip",
                False
            ),
            abuse_score=result.get(
                "abuse_score",
                0
            ),
            country=result.get(
                "country",
                "Unknown"
            ),
            isp=result.get(
                "isp",
                "Unknown"
            ),
            intelligence_source=result.get(
                "intelligence_source",
                "UNKNOWN"
            )
        )