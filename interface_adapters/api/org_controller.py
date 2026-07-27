from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query

from application.use_cases.assess_org_threat_relevance import (
    AssessOrgThreatRelevanceRequest,
)
from domain.value_objects.cii_sector import CIISector
from infrastructure.di.container import Container, get_container
from interface_adapters.api.error_mapping import run_with_gateway_error_mapping

router = APIRouter(prefix="/api/v1/org", tags=["Org Threat Relevance"])


@router.get("/assess")
async def assess_threat_relevance(
    sector: CIISector | None = Query(
        None, description="ระบุ CII sector โดยตรง (7 sectors ตาม พ.ร.บ.ไซเบอร์ฯ)"
    ),
    domain: str | None = Query(
        None, description="หรือระบุ domain name ขององค์กรแทน sector"
    ),
    container: Container = Depends(get_container),
) -> dict:
    if sector is None and domain is None:
        raise HTTPException(
            status_code=422, detail="ต้องระบุ sector หรือ domain อย่างน้อยหนึ่งอย่าง"
        )

    use_case = container.assess_org_threat_relevance_use_case()
    try:
        request = AssessOrgThreatRelevanceRequest(sector=sector, domain=domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = await run_with_gateway_error_mapping(use_case.execute(request))

    return {
        "matched_sector": result.matched_sector.value,
        "matched_sector_label_th": result.matched_sector.label_th,
        "sector_confidence": round(result.sector_confidence, 2),
        "relevant_threats": [
            {**asdict(t), "published": t.published.isoformat()}
            for t in result.relevant_threats
        ],
    }
