"""Phase 5: คำนวณ Risk Score รายพนักงาน จาก Exposure + Behavior + Threat Landscape"""
from dataclasses import dataclass

from application.ports.risk_engine import RiskEngine
from application.ports.threat_intel_gateway import ThreatIntelGateway
from domain.entities.employee import Employee
from domain.entities.risk_score import RiskScore
from domain.value_objects.cii_sector import CIISector


@dataclass(slots=True)
class ScoreEmployeeRiskRequest:
    employee: Employee
    sector: CIISector


class ScoreEmployeeRiskUseCase:
    """
    Business logic ล้วนๆ — ไม่รู้จัก MISP หรืออัลกอริทึมของ risk engine เลย
    รับแค่ ThreatIntelGateway (port) และ RiskEngine (port)
    """

    def __init__(self, risk_engine: RiskEngine, gateway: ThreatIntelGateway) -> None:
        self._risk_engine = risk_engine
        self._gateway = gateway

    async def execute(self, request: ScoreEmployeeRiskRequest) -> RiskScore:
        active_threats = await self._gateway.get_events_by_sector(request.sector.value)
        return await self._risk_engine.calculate(request.employee, active_threats)
