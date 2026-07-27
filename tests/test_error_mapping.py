import pytest
from fastapi import HTTPException

from domain.exceptions import ThreatIntelAuthError, ThreatIntelRateLimitError
from interface_adapters.api.error_mapping import run_with_gateway_error_mapping


async def _raise(exc: Exception):
    raise exc


@pytest.mark.asyncio
async def test_auth_error_maps_to_502():
    with pytest.raises(HTTPException) as exc_info:
        await run_with_gateway_error_mapping(_raise(ThreatIntelAuthError("bad key")))
    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_rate_limit_error_maps_to_503():
    # ThreatIntelRateLimitError เป็น subtype ของ ThreatIntelUnavailableError
    with pytest.raises(HTTPException) as exc_info:
        await run_with_gateway_error_mapping(_raise(ThreatIntelRateLimitError("too many calls")))
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_successful_coroutine_passes_through_unchanged():
    async def ok():
        return {"hello": "world"}

    result = await run_with_gateway_error_mapping(ok())
    assert result == {"hello": "world"}


def test_org_assess_endpoint_returns_503_when_rate_limited():
    from fastapi.testclient import TestClient
    from infrastructure.di.container import get_container
    from infrastructure.threat_intel.mock_gateway import MockThreatIntelGateway
    from infrastructure.threat_intel.rate_limited_gateway import RateLimitedThreatIntelGateway
    from main import app

    # บังคับให้ threat_intel_gateway ใน container โดน rate limit ทันที (max_calls=0)
    container = get_container()
    container.threat_intel_gateway.cache_clear()
    original_raw = container._raw_threat_intel_gateway()
    limited_zero = RateLimitedThreatIntelGateway(original_raw, max_calls=0, window_seconds=60)
    container.threat_intel_gateway = lambda: limited_zero  # monkeypatch instance method

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/v1/org/assess?sector=finance_banking")

    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"].lower()
