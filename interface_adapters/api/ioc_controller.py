from fastapi import APIRouter, Depends, HTTPException, Query

from application.use_cases.search_ioc import SearchIOCRequest
from domain.exceptions import ThreatIntelAuthError, ThreatIntelUnavailableError
from infrastructure.di.container import Container, get_container
from interface_adapters.presenters.json_presenter import present_search_ioc_response

router = APIRouter(prefix="/api/v1/ioc", tags=["IOC"])


@router.get("/search")
async def search_ioc(
    value: str = Query(..., min_length=1, description="ค่า IOC เช่น IP, domain, hash"),
    ioc_type: str | None = Query(None, description="ตัวกรองชนิด IOC เช่น ip-dst, domain, sha256"),
    container: Container = Depends(get_container),
) -> dict:
    use_case = container.search_ioc_use_case()
    try:
        result = await use_case.execute(
            SearchIOCRequest(value=value, ioc_type=ioc_type)
        )
    except ThreatIntelAuthError as exc:
        raise HTTPException(
            status_code=502, detail="Threat intel provider authentication failed"
        ) from exc
    except ThreatIntelUnavailableError as exc:
        raise HTTPException(
            status_code=503, detail="Threat intel provider unavailable, no cache available"
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return present_search_ioc_response(result)
