from abc import ABC, abstractmethod
from datetime import datetime

from domain.entities.ioc import IOC
from domain.entities.threat import ThreatEvent


class ThreatIntelGateway(ABC):
    """
    Port กลางสำหรับ Threat Intel Provider ใดๆ (MISP, OTX, custom feed).

    Business logic (use cases) เรียกผ่าน interface นี้เท่านั้น — ไม่รู้จัก MISP โดยตรง
    การเปลี่ยน provider ในอนาคต = เขียน adapter ใหม่ implement interface นี้
    ไม่ต้องแก้ use case หรือ entity ใดๆ เลย
    """

    @abstractmethod
    async def search_ioc(self, value: str, ioc_type: str | None = None) -> list[IOC]:
        """ค้นหา IOC ตามค่า (hash, ip, domain, url ฯลฯ)"""
        raise NotImplementedError

    @abstractmethod
    async def get_events_since(
        self, since: datetime, tags: list[str] | None = None
    ) -> list[ThreatEvent]:
        """ดึง threat event ใหม่ตามช่วงเวลา และกรองตาม tag"""
        raise NotImplementedError

    @abstractmethod
    async def get_events_by_sector(self, sector_tag: str) -> list[ThreatEvent]:
        """ดึง event ที่ tag ตรงกับ CII sector ที่ระบุ"""
        raise NotImplementedError
