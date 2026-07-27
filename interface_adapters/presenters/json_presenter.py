from dataclasses import asdict

from application.use_cases.search_ioc import SearchIOCResponse


def present_search_ioc_response(response: SearchIOCResponse) -> dict:
    return {
        "degraded": response.degraded,
        "count": len(response.results),
        "results": [asdict(ioc) for ioc in response.results],
    }
