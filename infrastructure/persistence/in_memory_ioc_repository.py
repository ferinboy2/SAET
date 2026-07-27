from application.ports.ioc_repository import IOCRepository
from domain.entities.ioc import IOC


class InMemoryIOCRepository(IOCRepository):
    """
    Cache แบบง่ายในหน่วยความจำ สำหรับ dev/test
    Production ควรแทนที่ด้วย Redis/Postgres adapter ที่ implement IOCRepository เหมือนกัน
    """

    def __init__(self) -> None:
        self._store: dict[str, list[IOC]] = {}

    async def get_cached_ioc(self, value: str) -> list[IOC]:
        return self._store.get(value, [])

    async def save_iocs(self, iocs: list[IOC]) -> None:
        for ioc in iocs:
            self._store.setdefault(ioc.value, [])
            if ioc not in self._store[ioc.value]:
                self._store[ioc.value].append(ioc)
