from typing import Awaitable, TypeVar

from fastapi import HTTPException

from domain.exceptions import ThreatIntelAuthError, ThreatIntelUnavailableError

T = TypeVar("T")


async def run_with_gateway_error_mapping(coro: Awaitable[T]) -> T:
    """
    Helper กลางที่ controller ทุกตัวที่เรียก use case ซึ่งอาจแตะ ThreatIntelGateway
    (โดยตรงหรือผ่าน use case อื่น) ใช้ร่วมกัน — แปล exception จาก domain layer
    เป็น HTTP status ที่สื่อความหมายถูกต้อง แทนที่จะหลุดไปเป็น 500 ทั่วไป

    ThreatIntelRateLimitError เป็น subtype ของ ThreatIntelUnavailableError อยู่แล้ว
    (ดู domain/exceptions.py) จึงถูกจับด้วย except เดียวกันโดยอัตโนมัติ
    """
    try:
        return await coro
    except ThreatIntelAuthError as exc:
        raise HTTPException(
            status_code=502, detail="Threat intel provider authentication failed"
        ) from exc
    except ThreatIntelUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail="Threat intel provider unavailable (rate limited หรือ connection ล้มเหลว)",
        ) from exc
