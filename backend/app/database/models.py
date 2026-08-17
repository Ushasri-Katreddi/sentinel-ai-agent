from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from datetime import datetime

from app.database.database import Base


class ThreatAnalysis(Base):

    __tablename__ = "threat_analyses"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, default=datetime.utcnow)

    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)

    username = Column(String, nullable=True)
    event = Column(String, nullable=True)
    failed_attempts = Column(Integer, nullable=True)

    score = Column(Integer, nullable=False)
    severity = Column(String, nullable=False)

    attack = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)

    recommendation = Column(String, nullable=False)

    malicious_ip = Column(Boolean, default=False)
    abuse_score = Column(Integer, default=0)

    country = Column(String, nullable=True)
    isp = Column(String, nullable=True)

    intelligence_source = Column(String, nullable=False)

    score_breakdown = Column(String, nullable=True)
