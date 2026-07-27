from abc import ABC, abstractmethod

from domain.entities.employee import Employee
from domain.entities.risk_score import RiskScore
from domain.entities.threat import ThreatEvent


class RiskEngine(ABC):
    """
    Port สำหรับ engine คำนวณความเสี่ยงรายบุคคล/ทีม.
    เปลี่ยนอัลกอริทึม (rule-based -> ML model) ได้โดยไม่กระทบ use case ที่เรียกใช้
    """

    @abstractmethod
    async def calculate(
        self, employee: Employee, active_threats: list[ThreatEvent]
    ) -> RiskScore:
        raise NotImplementedError
