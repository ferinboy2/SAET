import asyncio
import logging
import time
from collections import deque
from datetime import datetime

from application.ports.threat_intel_gateway import ThreatIntelGateway
from domain.entities.ioc import IOC
from domain.entities.threat import ThreatEvent
from domain.exceptions import ThreatIntelRateLimitError

logger = logging.getLogger(__name__)


class RateLimitedThreatIntelGateway(ThreatIntelGateway):
    """
    Decorator ที่ wrap ThreatIntelGateway ใดๆ (MISP, mock, หรือ provider อื่น) ด้วย
    sliding-window rate limit ฝั่งเราเอง — ป้องกันไม่ให้ SA&ET ยิง MISP ถี่เกินไป
    จนโดน provider เองยกเลิก access หรือ throttle เรา

    ยัง implement ThreatIntelGateway port เดิม เพียงแค่ "ห่อ" gateway จริงไว้ข้างใน
    ดังนั้น use case/controller ไม่รู้เลยว่ามี rate limiter อยู่ — สลับเปิด/ปิด
    ได้จาก DI container จุดเดียว

    ใช้ fail-fast แทน queue: ถ้าเกิน limit จะ raise ทันที (ไม่ block รอ) เพื่อให้ผู้เรียก
    (เช่น SearchIOCUseCase) fallback ไป cache ได้เร็ว แทนที่จะให้ผู้ใช้รอเฉยๆ
    """

    def __init__(
        self,
        wrapped: ThreatIntelGateway,
        max_calls: int = 30,
        window_seconds: float = 60.0,
    ) -> None:
        self._wrapped = wrapped
        self._max_calls = max_calls
        self._window_seconds = window_seconds
        self._call_timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def _check_rate_limit(self, operation: str) -> None:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_seconds
            while self._call_timestamps and self._call_timestamps[0] < cutoff:
                self._call_timestamps.popleft()

            if len(self._call_timestamps) >= self._max_calls:
                logger.warning(
                    "Rate limit exceeded for threat intel gateway operation=%s (%d calls / %.0fs window)",
                    operation,
                    self._max_calls,
                    self._window_seconds,
                )
                raise ThreatIntelRateLimitError(
                    f"เกิน rate limit ({self._max_calls} calls / {self._window_seconds:.0f}s) "
                    f"สำหรับ operation '{operation}'"
                )

            self._call_timestamps.append(now)

    async def search_ioc(self, value: str, ioc_type: str | None = None) -> list[IOC]:
        await self._check_rate_limit("search_ioc")
        return await self._wrapped.search_ioc(value, ioc_type)

    async def get_events_since(
        self, since: datetime, tags: list[str] | None = None
    ) -> list[ThreatEvent]:
        await self._check_rate_limit("get_events_since")
        return await self._wrapped.get_events_since(since, tags)

    async def get_events_by_sector(self, sector_tag: str) -> list[ThreatEvent]:
        await self._check_rate_limit("get_events_by_sector")
        return await self._wrapped.get_events_by_sector(sector_tag)
