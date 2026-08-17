from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class ThreatAnalysis(Base):
    __tablename__ = "threat_analyses"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=True,
    )

    username: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
    )

    event: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
    )

    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=True,
    )

    country: Mapped[str] = mapped_column(
        String(100),
        nullable=True,
    )

    device: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
    )

    # Threat analysis
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    attack: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    recommendation: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    # Score explanation
    score_breakdown: Mapped[dict] = mapped_column(
        JSON,
        nullable=True,
    )

    # IOC intelligence
    malicious_ip: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    abuse_score: Mapped[int] = mapped_column(
        Integer,
        nullable=True,
    )

    ioc_country: Mapped[str] = mapped_column(
        String(100),
        nullable=True,
    )

    isp: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
    )

    intelligence_source: Mapped[str] = mapped_column(
        String(100),
        nullable=True,
    )