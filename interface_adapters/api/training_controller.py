from fastapi import APIRouter, Depends, HTTPException

from application.use_cases.generate_training import GenerateTrainingRequest
from application.use_cases.score_employee_risk import ScoreEmployeeRiskRequest
from domain.entities.employee import Employee
from domain.exceptions import AIGenerationError
from infrastructure.di.container import Container, get_container
from interface_adapters.api.error_mapping import run_with_gateway_error_mapping
from interface_adapters.api.risk_controller import ScoreEmployeeRiskBody

router = APIRouter(prefix="/api/v1/training", tags=["Training Generator"])


@router.post("/generate")
async def generate_training_for_employee(
    body: ScoreEmployeeRiskBody, container: Container = Depends(get_container)
) -> dict:
    """
    รวม Phase 5 (Risk Engine) + Phase 6 (Training Generator) ในคำขอเดียว:
    1. คำนวณ Risk Score ของพนักงานตาม sector ที่ระบุ
    2. ส่ง Risk Score นั้นให้ AI content generator สร้างเนื้อหา training ที่ตรงจุด
    """
    employee = Employee(
        id=body.employee.id,
        name=body.employee.name,
        department=body.employee.department,
        access_level=body.employee.access_level,
        email=body.employee.email,
        recent_phishing_click_rate=body.employee.recent_phishing_click_rate,
        completed_trainings=body.employee.completed_trainings,
    )

    risk_score = await run_with_gateway_error_mapping(
        container.score_employee_risk_use_case().execute(
            ScoreEmployeeRiskRequest(employee=employee, sector=body.sector)
        )
    )

    try:
        training = await container.generate_training_use_case().execute(
            GenerateTrainingRequest(
                risk_score=risk_score, employee_department=employee.department
            )
        )
    except AIGenerationError as exc:
        raise HTTPException(
            status_code=502, detail=f"AI content generation ล้มเหลวทั้ง primary และ fallback: {exc}"
        ) from exc

    return {
        "employee_id": risk_score.employee_id,
        "risk_level": risk_score.level,
        "risk_total_score": risk_score.total_score,
        "training": {
            "title_th": training.title_th,
            "content_th": training.content_th,
            "priority": training.priority,
            "generated_by": training.generated_by,
        },
    }
