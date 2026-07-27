from abc import ABC, abstractmethod
from domain.entities.ioc import IOC


class IOCRepository(ABC):
    """
    Port สำหรับ persistence/cache ของ IOC (เช่น Postgres, Redis)
    ใช้เป็น fallback เมื่อ ThreatIntelGateway ล่ม (ThreatIntelUnavailableError)
    """

    @abstractmethod
    async def get_cached_ioc(self, value: str) -> list[IOC]:
        raise NotImplementedError

    @abstractmethod
    async def save_iocs(self, iocs: list[IOC]) -> None:
        raise NotImplementedError
