from datetime import datetime, timezone

from application.ports.risk_engine import RiskEngine
from domain.entities.employee import AccessLevel, Employee
from domain.entities.risk_score import RiskScore, RiskScoreBreakdown
from domain.entities.threat import ThreatEvent
from infrastructure.attack.attack_technique_catalog import lookup_technique

# น้ำหนักแต่ละมิติ รวมกันต้องเท่ากับ 1.0 — ปรับได้ตามนโยบายองค์กร
_WEIGHT_EXPOSURE = 0.35
_WEIGHT_BEHAVIOR = 0.35
_WEIGHT_THREAT_LANDSCAPE = 0.30

_ACCESS_LEVEL_BASE_SCORE: dict[AccessLevel, float] = {
    AccessLevel.STANDARD: 20.0,
    AccessLevel.PRIVILEGED: 60.0,
    AccessLevel.EXECUTIVE: 80.0,  # C-level มักโดน BEC/spear-phishing เป็นเป้าหมายหลัก
}

_MAX_TRAINING_RISK_REDUCTION = 30.0   # ลดความเสี่ยง behavior ได้สูงสุดจากการอบรมที่ผ่านแล้ว
_TRAINING_REDUCTION_PER_ITEM = 10.0
_THREAT_LANDSCAPE_BASELINE = 10.0     # แม้ไม่มี threat active ก็ยังมีความเสี่ยงพื้นฐาน
_THREAT_LANDSCAPE_PER_EVENT = 20.0
_MAX_RECOMMENDED_TAGS = 5


class RuleBasedRiskEngine(RiskEngine):
    """
    Risk Engine แบบ rule-based (ไม่ใช้ ML) — โปร่งใส ตรวจสอบย้อนกลับได้ง่ายว่าทำไม
    ถึงได้คะแนนเท่านี้ ซึ่งสำคัญเวลาต้องอธิบายผลให้ผู้บริหาร/พนักงานฟัง

    เปลี่ยนไปใช้โมเดล ML ในอนาคตได้ โดยเขียน engine ใหม่ implement RiskEngine
    (application/ports/risk_engine.py) แทนที่นี่ ไม่กระทบ use case/controller
    """

    async def calculate(
        self, employee: Employee, active_threats: list[ThreatEvent]
    ) -> RiskScore:
        exposure = self._compute_exposure(employee)
        behavior = self._compute_behavior(employee)
        threat_landscape = self._compute_threat_landscape(active_threats)

        total = (
            exposure * _WEIGHT_EXPOSURE
            + behavior * _WEIGHT_BEHAVIOR
            + threat_landscape * _WEIGHT_THREAT_LANDSCAPE
        )

        return RiskScore(
            employee_id=employee.id,
            total_score=round(total, 1),
            breakdown=RiskScoreBreakdown(
                exposure=round(exposure, 1),
                behavior=round(behavior, 1),
                threat_landscape=round(threat_landscape, 1),
            ),
            calculated_at=datetime.now(timezone.utc),
            recommended_training_tags=self._recommend_training_tags(
                active_threats, employee
            ),
        )

    @staticmethod
    def _compute_exposure(employee: Employee) -> float:
        """คะแนน Exposure: อิงจากระดับสิทธิ์การเข้าถึงระบบ ยิ่งสิทธิ์สูงยิ่งเป็นเป้าหมายที่มีมูลค่า"""
        return _ACCESS_LEVEL_BASE_SCORE.get(employee.access_level, 20.0)

    @staticmethod
    def _compute_behavior(employee: Employee) -> float:
        """
        คะแนน Behavior: อิงจากอัตราการคลิก phishing simulation ล่าสุด
        หักลดจากจำนวน training ที่ผ่านแล้ว (การอบรมช่วยลดความเสี่ยงเชิงพฤติกรรมได้จริง)
        """
        click_risk = employee.recent_phishing_click_rate * 100.0
        training_reduction = min(
            _MAX_TRAINING_RISK_REDUCTION,
            len(employee.completed_trainings) * _TRAINING_REDUCTION_PER_ITEM,
        )
        return max(0.0, min(100.0, click_risk - training_reduction))

    @staticmethod
    def _compute_threat_landscape(active_threats: list[ThreatEvent]) -> float:
        """คะแนน Threat Landscape: ยิ่ง sector มี threat event active มากเท่าไหร่ ความเสี่ยงยิ่งสูง"""
        if not active_threats:
            return _THREAT_LANDSCAPE_BASELINE
        score = _THREAT_LANDSCAPE_BASELINE + len(active_threats) * _THREAT_LANDSCAPE_PER_EVENT
        return min(100.0, score)

    @staticmethod
    def _recommend_training_tags(
        active_threats: list[ThreatEvent], employee: Employee
    ) -> list[str]:
        """
        แนะนำหัวข้อ training จาก MITRE ATT&CK technique ที่พบใน threat ที่ active
        กับ sector ของพนักงาน โดยไม่แนะนำหัวข้อที่พนักงานผ่านการอบรมไปแล้ว
        """
        tags: set[str] = set()
        for threat in active_threats:
            for ttp_id in threat.ttp_ids:
                technique = lookup_technique(ttp_id)
                if technique is not None:
                    tags.add(technique.name)

        tags -= set(employee.completed_trainings)
        return sorted(tags)[:_MAX_RECOMMENDED_TAGS]
