from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends

from application.use_cases.score_employee_risk import ScoreEmployeeRiskRequest
from domain.entities.employee import AccessLevel, Employee
from domain.value_objects.cii_sector import CIISector
from infrastructure.di.container import Container, get_container
from interface_adapters.api.error_mapping import run_with_gateway_error_mapping

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Engine"])


class EmployeeInput(BaseModel):
    id: str
    name: str
    department: str
    access_level: AccessLevel = AccessLevel.STANDARD
    email: str | None = None
    recent_phishing_click_rate: float = Field(0.0, ge=0.0, le=1.0)
    completed_trainings: list[str] = []


class ScoreEmployeeRiskBody(BaseModel):
    employee: EmployeeInput
    sector: CIISector


@router.post("/score")
async def score_employee(
    body: ScoreEmployeeRiskBody, container: Container = Depends(get_container)
) -> dict:
    employee = Employee(
        id=body.employee.id,
        name=body.employee.name,
        department=body.employee.department,
        access_level=body.employee.access_level,
        email=body.employee.email,
        recent_phishing_click_rate=body.employee.recent_phishing_click_rate,
        completed_trainings=body.employee.completed_trainings,
    )

    use_case = container.score_employee_risk_use_case()
    risk_score = await run_with_gateway_error_mapping(
        use_case.execute(ScoreEmployeeRiskRequest(employee=employee, sector=body.sector))
    )

    return {
        "employee_id": risk_score.employee_id,
        "total_score": risk_score.total_score,
        "level": risk_score.level,
        "breakdown": {
            "exposure": risk_score.breakdown.exposure,
            "behavior": risk_score.breakdown.behavior,
            "threat_landscape": risk_score.breakdown.threat_landscape,
        },
        "recommended_training_tags": risk_score.recommended_training_tags,
        "calculated_at": risk_score.calculated_at.isoformat(),
    }
