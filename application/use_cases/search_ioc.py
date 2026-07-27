import logging
from dataclasses import dataclass, field

from application.ports.ioc_repository import IOCRepository
from application.ports.threat_intel_gateway import ThreatIntelGateway
from domain.entities.ioc import IOC
from domain.exceptions import ThreatIntelUnavailableError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SearchIOCRequest:
    value: str
    ioc_type: str | None = None


@dataclass(slots=True)
class SearchIOCResponse:
    results: list[IOC] = field(default_factory=list)
    degraded: bool = False  # True = provider ล่ม, ตอบจาก cache แทน


class SearchIOCUseCase:
    """
    Business logic ล้วนๆ — ไม่รู้จัก MISP เลย รับแค่ ThreatIntelGateway (port)
    และ IOCRepository (port) สำหรับ cache fallback
    """

    def __init__(
        self,
        gateway: ThreatIntelGateway,
        cache_repo: IOCRepository | None = None,
    ) -> None:
        self._gateway = gateway
        self._cache = cache_repo

    async def execute(self, request: SearchIOCRequest) -> SearchIOCResponse:
        if not request.value or not request.value.strip():
            raise ValueError("IOC value must not be empty")

        try:
            results = await self._gateway.search_ioc(request.value, request.ioc_type)
        except ThreatIntelUnavailableError:
            logger.warning(
                "Threat intel provider unavailable, falling back to cache for value=%s",
                request.value,
            )
            if self._cache is None:
                raise
            cached = await self._cache.get_cached_ioc(request.value)
            return SearchIOCResponse(results=cached, degraded=True)

        if self._cache is not None and results:
            await self._cache.save_iocs(results)

        return SearchIOCResponse(results=results, degraded=False)
