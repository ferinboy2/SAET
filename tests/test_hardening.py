from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from domain.exceptions import ThreatIntelRateLimitError, ThreatIntelUnavailableError
from infrastructure.threat_intel.mock_gateway import MockThreatIntelGateway
from infrastructure.threat_intel.rate_limited_gateway import RateLimitedThreatIntelGateway


@pytest.mark.asyncio
async def test_rate_limiter_allows_calls_within_limit():
    wrapped = MockThreatIntelGateway()
    limited = RateLimitedThreatIntelGateway(wrapped, max_calls=3, window_seconds=60)

    for _ in range(3):
        result = await limited.search_ioc("1.2.3.4")
        assert isinstance(result, list)


@pytest.mark.asyncio
async def test_rate_limiter_blocks_call_beyond_limit():
    wrapped = MockThreatIntelGateway()
    limited = RateLimitedThreatIntelGateway(wrapped, max_calls=2, window_seconds=60)

    await limited.search_ioc("1.2.3.4")
    await limited.search_ioc("1.2.3.4")

    with pytest.raises(ThreatIntelRateLimitError):
        await limited.search_ioc("1.2.3.4")


def test_rate_limit_error_is_subtype_of_unavailable_error():
    # เพื่อให้ use case ที่ catch ThreatIntelUnavailableError (เช่น SearchIOCUseCase)
    # fallback ไป cache ได้อัตโนมัติแม้สาเหตุจะเป็น rate limit ก็ตาม
    assert issubclass(ThreatIntelRateLimitError, ThreatIntelUnavailableError)


@pytest.mark.asyncio
async def test_rate_limiter_resets_after_window_expires():
    wrapped = MockThreatIntelGateway()
    limited = RateLimitedThreatIntelGateway(wrapped, max_calls=1, window_seconds=10)

    with patch("infrastructure.threat_intel.rate_limited_gateway.time.monotonic") as mock_time:
        mock_time.return_value = 0.0
        await limited.search_ioc("1.2.3.4")

        mock_time.return_value = 5.0  # ยังอยู่ใน window (10s) -> ควรโดน block
        with pytest.raises(ThreatIntelRateLimitError):
            await limited.search_ioc("1.2.3.4")

        mock_time.return_value = 11.0  # พ้น window แล้ว -> ควรผ่านได้อีกครั้ง
        result = await limited.search_ioc("1.2.3.4")
        assert isinstance(result, list)


@pytest.mark.asyncio
async def test_rate_limiter_delegates_all_gateway_methods():
    wrapped = MockThreatIntelGateway()
    limited = RateLimitedThreatIntelGateway(wrapped, max_calls=10, window_seconds=60)

    events_since = await limited.get_events_since(since=datetime(2020, 1, 1))
    events_by_sector = await limited.get_events_by_sector("finance_banking")

    assert isinstance(events_since, list)
    assert len(events_by_sector) == 1


def test_health_endpoint_returns_request_id_header():
    from main import app

    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "x-request-id" in {k.lower() for k in response.headers.keys()}


def test_unhandled_exception_returns_generic_500_without_leaking_details():
    from main import app

    @app.get("/__test_boom")
    async def boom():
        raise RuntimeError("ข้อมูลลับที่ไม่ควรหลุดไปหา client")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/__test_boom")

    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "internal server error"
    assert "request_id" in body
    assert "ข้อมูลลับ" not in response.text
