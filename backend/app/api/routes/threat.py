from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.threat_analysis import ThreatAnalysis
from app.schemas.threat import ThreatLog
from app.services.threat_service import ThreatService


router = APIRouter()


@router.post("/analyze-log")
def analyze_log(log: ThreatLog):
    return ThreatService.analyze(log)


@router.get("/threats")
def get_threats(db: Session = Depends(get_db)):
    threats = (
        db.query(ThreatAnalysis)
        .order_by(ThreatAnalysis.id.desc())
        .all()
    )

    return threats