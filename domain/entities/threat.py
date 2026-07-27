from dataclasses import dataclass, field
from datetime import datetime
from domain.entities.ioc import IOC


@dataclass(frozen=True, slots=True)
class ThreatEvent:
    """เหตุการณ์ภัยคุกคาม 1 รายการ จาก threat intel provider ใดๆ"""

    id: str
    title: str
    source: str
    published: datetime
    tags: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    ttp_ids: list[str] = field(default_factory=list)   # เช่น ["T1566", "T1059.001"]
    raw_severity: str | None = None                    # low/medium/high/critical ตาม provider

    def relevant_to_sector(self, sector_tag: str) -> bool:
        return sector_tag in self.tags
