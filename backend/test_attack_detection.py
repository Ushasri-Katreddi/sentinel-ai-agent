from app.engines.threat_engine import ThreatEngine
from app.schemas.threat import ThreatLog


log = ThreatLog(
    timestamp="2026-08-18T10:00:00",
    source_ip="10.10.10.50",
    destination_ip="192.168.1.10",
    username="test_user",
    event="Port scan detected from external source",
    failed_attempts=0,
    country="US",
    device="Network Gateway"
)


attack = ThreatEngine.detect_attack(log)

confidence = ThreatEngine.calculate_confidence(
    log,
    attack
)


print("Attack Type:", attack)
print("Confidence:", confidence)