from datetime import datetime

from pydantic import BaseModel


class ThreatLog(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    username: str
    event: str
    failed_attempts: int
    country: str
    device: str