from datetime import datetime

from application.ports.threat_intel_gateway import ThreatIntelGateway
from domain.entities.ioc import IOC
from domain.entities.threat import ThreatEvent
from domain.exceptions import ThreatIntelUnavailableError


class MockThreatIntelGateway(ThreatIntelGateway):
    """
    In-memory implementation ของ ThreatIntelGateway สำหรับ dev/test
    โดยไม่ต้องมี MISP instance จริง — ใช้ในระหว่างพัฒนา Phase 3-6
    ก่อนที่ MISP instance จริงจะพร้อม, และใช้เป็น test double ใน unit test
    """

    def __init__(self, simulate_outage: bool = False) -> None:
        self._simulate_outage = simulate_outage
        self._iocs: dict[str, list[IOC]] = {
            "1.2.3.4": [
                IOC(
                    value="1.2.3.4",
                    type="ip-dst",
                    source="MOCK",
                    first_seen=datetime(2026, 6, 1),
                    tags=["sector:finance_banking", "malware:emotet"],
                    confidence=80,
                )
            ]
        }
        self._events_by_sector: dict[str, list[ThreatEvent]] = {
            "finance_banking": [
                ThreatEvent(
                    id="evt-001",
                    title="BEC campaign targeting Thai banks",
                    source="MOCK",
                    published=datetime(2026, 7, 10),
                    tags=["sector:finance_banking"],
                    ttp_ids=["T1566.002", "T1078"],
                )
            ],
            "public_service": [
                ThreatEvent(
                    id="evt-002",
                    title="Ransomware targeting government agencies in Southeast Asia",
                    source="MOCK",
                    published=datetime(2026, 7, 5),
                    tags=["sector:public_service"],
                    ttp_ids=["T1486", "T1078"],
                )
            ],
        }

    async def search_ioc(self, value: str, ioc_type: str | None = None) -> list[IOC]:
        if self._simulate_outage:
            raise ThreatIntelUnavailableError("Simulated outage for testing")
        results = self._iocs.get(value, [])
        if ioc_type:
            results = [i for i in results if i.type == ioc_type]
        return results

    async def get_events_since(
        self, since: datetime, tags: list[str] | None = None
    ) -> list[ThreatEvent]:
        if self._simulate_outage:
            raise ThreatIntelUnavailableError("Simulated outage for testing")
        all_events = [e for events in self._events_by_sector.values() for e in events]
        return [e for e in all_events if e.published >= since]

    async def get_events_by_sector(self, sector_tag: str) -> list[ThreatEvent]:
        if self._simulate_outage:
            raise ThreatIntelUnavailableError("Simulated outage for testing")
        return self._events_by_sector.get(sector_tag, [])
