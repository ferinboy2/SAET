from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class IOC:
    """Indicator of Compromise — ไม่รู้จักว่ามาจาก provider ใด (MISP/OTX/ฯลฯ)"""

    value: str
    type: str                          # ip, domain, url, md5, sha256, email, ...
    source: str                        # ชื่อ provider ที่ส่งมา เช่น "MISP"
    first_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    confidence: int | None = None      # 0-100 ถ้า provider ให้มา

    def matches_sector_tag(self, sector_tag: str) -> bool:
        return sector_tag in self.tags
