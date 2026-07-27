from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class RiskScoreBreakdown:
    """คะแนนย่อยแต่ละมิติ 0-100 ก่อนถ่วงน้ำหนักรวม"""

    exposure: float
    behavior: float
    threat_landscape: float


@dataclass(frozen=True, slots=True)
class RiskScore:
    employee_id: str
    total_score: float                       # 0-100 ถ่วงน้ำหนักแล้ว
    breakdown: RiskScoreBreakdown
    calculated_at: datetime
    recommended_training_tags: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.total_score >= 75:
            return "critical"
        if self.total_score >= 50:
            return "high"
        if self.total_score >= 25:
            return "medium"
        return "low"
