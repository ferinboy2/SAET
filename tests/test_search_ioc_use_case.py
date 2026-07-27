import pytest

from application.use_cases.search_ioc import SearchIOCRequest, SearchIOCUseCase
from infrastructure.persistence.in_memory_ioc_repository import InMemoryIOCRepository
from infrastructure.threat_intel.mock_gateway import MockThreatIntelGateway


@pytest.mark.asyncio
async def test_search_ioc_returns_results_when_gateway_healthy():
    gateway = MockThreatIntelGateway(simulate_outage=False)
    cache = InMemoryIOCRepository()
    use_case = SearchIOCUseCase(gateway=gateway, cache_repo=cache)

    response = await use_case.execute(SearchIOCRequest(value="1.2.3.4"))

    assert response.degraded is False
    assert len(response.results) == 1
    assert response.results[0].value == "1.2.3.4"


@pytest.mark.asyncio
async def test_search_ioc_falls_back_to_cache_when_gateway_down():
    healthy_gateway = MockThreatIntelGateway(simulate_outage=False)
    cache = InMemoryIOCRepository()
    warm_up = SearchIOCUseCase(gateway=healthy_gateway, cache_repo=cache)
    await warm_up.execute(SearchIOCRequest(value="1.2.3.4"))

    down_gateway = MockThreatIntelGateway(simulate_outage=True)
    use_case = SearchIOCUseCase(gateway=down_gateway, cache_repo=cache)

    response = await use_case.execute(SearchIOCRequest(value="1.2.3.4"))

    assert response.degraded is True
    assert len(response.results) == 1


@pytest.mark.asyncio
async def test_search_ioc_raises_when_gateway_down_and_no_cache():
    down_gateway = MockThreatIntelGateway(simulate_outage=True)
    use_case = SearchIOCUseCase(gateway=down_gateway, cache_repo=None)

    with pytest.raises(Exception):
        await use_case.execute(SearchIOCRequest(value="1.2.3.4"))


@pytest.mark.asyncio
async def test_search_ioc_rejects_empty_value():
    gateway = MockThreatIntelGateway()
    use_case = SearchIOCUseCase(gateway=gateway)

    with pytest.raises(ValueError):
        await use_case.execute(SearchIOCRequest(value="   "))
