from fastapi import APIRouter, Depends, HTTPException, Query

from application.use_cases.map_to_attack import MapToAttackRequest
from domain.entities.attack_technique import AttackTechnique
from domain.exceptions import AttackMappingError
from domain.value_objects.cii_sector import CIISector
from infrastructure.di.container import Container, get_container
from interface_adapters.api.error_mapping import run_with_gateway_error_mapping

router = APIRouter(prefix="/api/v1/attack", tags=["ATT&CK Mapping"])


def _technique_to_dict(t: AttackTechnique) -> dict:
    return {
        "technique_id": t.technique_id,
        "name": t.name,
        "tactic": t.tactic,
        "prevent": t.prevent_guidance,
        "detect": t.detect_guidance,
        "respond": t.respond_guidance,
    }


@router.get("/mapping")
async def get_attack_mapping_for_sector(
    sector: CIISector = Query(..., description="CII sector ที่ต้องการดู ATT&CK mapping"),
    container: Container = Depends(get_container),
) -> dict:
    """
    ดึง threat event ที่ active กับ sector นี้ทั้งหมด แล้ว map แต่ละ event
    เป็น MITRE ATT&CK Technique พร้อมคำแนะนำ Prevent/Detect/Respond
    """
    gateway = container.threat_intel_gateway()
    threats = await run_with_gateway_error_mapping(gateway.get_events_by_sector(sector.value))

    map_use_case = container.map_to_attack_use_case()

    mapping_result = []
    for threat in threats:
        try:
            techniques = map_use_case.execute(MapToAttackRequest(threat=threat))
        except AttackMappingError:
            techniques = []
        mapping_result.append(
            {
                "threat_id": threat.id,
                "threat_title": threat.title,
                "techniques": [_technique_to_dict(t) for t in techniques],
            }
        )

    return {"sector": sector.value, "threat_count": len(threats), "mapping": mapping_result}


@router.get("/technique/{technique_id}")
async def get_technique_detail(technique_id: str) -> dict:
    """Lookup รายละเอียด technique เดี่ยวๆ ตาม ID (สำหรับ UI ที่อยากแสดงรายละเอียดแยก)"""
    from infrastructure.attack.attack_technique_catalog import lookup_technique

    technique = lookup_technique(technique_id)
    if technique is None:
        raise HTTPException(status_code=404, detail=f"ไม่พบ technique '{technique_id}' ใน catalog")
    return _technique_to_dict(technique)
