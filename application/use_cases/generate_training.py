"""Phase 6: สร้างเนื้อหา Awareness/Training ภาษาไทย ตาม Risk Score ที่คำนวณจาก Risk Engine (Phase 5)"""
from dataclasses import dataclass

from application.ports.ai_content_generator import AIContentGenerator
from domain.entities.risk_score import RiskScore
from domain.exceptions import AIGenerationError

_SYSTEM_PROMPT = (
    "คุณเป็นผู้เชี่ยวชาญด้าน security awareness training ในองค์กรไทย "
    "เขียนเนื้อหาภาษาไทยที่กระชับ เข้าใจง่ายสำหรับพนักงานทั่วไปที่ไม่ใช่สายเทคนิค "
    "หลีกเลี่ยงศัพท์เทคนิคที่ซับซ้อนเกินไป เน้นสิ่งที่พนักงานทำได้จริงในชีวิตประจำวัน"
)


@dataclass(slots=True)
class GenerateTrainingRequest:
    risk_score: RiskScore
    employee_department: str = ""


@dataclass(slots=True)
class GenerateTrainingResponse:
    title_th: str
    content_th: str
    priority: str          # จาก risk_score.level: low/medium/high/critical
    generated_by: str      # "ai" หรือ "template" (บอกว่าเนื้อหามาจาก AI จริงหรือ fallback)


class GenerateTrainingUseCase:
    """
    รับ RiskScore ที่คำนวณมาแล้วจาก ScoreEmployeeRiskUseCase (Phase 5) พร้อม
    recommended_training_tags ที่มาจาก MITRE ATT&CK mapping (Phase 4)
    แล้วสร้าง prompt ส่งให้ AIContentGenerator (port) เพื่อ generate เนื้อหาไทย

    ถ้า AI provider หลักล้มเหลว (AIGenerationError) และมี fallback_generator
    ให้ fallback ไปใช้แทนโดยอัตโนมัติ แทนที่จะให้ผู้ใช้ได้ error เปล่าๆ
    """

    def __init__(
        self,
        ai_generator: AIContentGenerator,
        fallback_generator: AIContentGenerator | None = None,
    ) -> None:
        self._ai_generator = ai_generator
        self._fallback_generator = fallback_generator

    async def execute(self, request: GenerateTrainingRequest) -> GenerateTrainingResponse:
        user_prompt = self._build_user_prompt(request)

        try:
            content = await self._ai_generator.generate(_SYSTEM_PROMPT, user_prompt)
            generated_by = "ai"
        except AIGenerationError:
            if self._fallback_generator is None:
                raise
            content = await self._fallback_generator.generate(_SYSTEM_PROMPT, user_prompt)
            generated_by = "template"

        return GenerateTrainingResponse(
            title_th=self._derive_title(request),
            content_th=content,
            priority=request.risk_score.level,
            generated_by=generated_by,
        )

    @staticmethod
    def _build_user_prompt(request: GenerateTrainingRequest) -> str:
        tags = request.risk_score.recommended_training_tags
        topics = ", ".join(tags) if tags else "ความเสี่ยงทั่วไปด้านความปลอดภัยไซเบอร์"
        dept = request.employee_department or "พนักงานทั่วไป"

        return (
            f"เขียนเนื้อหา security awareness training ความยาวประมาณ 300-400 คำ "
            f"สำหรับพนักงานแผนก {dept}\n"
            f"ระดับความเสี่ยงของพนักงานคนนี้: {request.risk_score.level}\n"
            f"หัวข้อที่ต้องครอบคลุม (จาก MITRE ATT&CK ที่เกี่ยวข้อง): {topics}\n\n"
            "โครงสร้างที่ต้องการ:\n"
            "1. สถานการณ์ตัวอย่างที่ใกล้เคียงกับความเสี่ยงจริง\n"
            "2. สิ่งที่ควรทำและไม่ควรทำ (bullet point)\n"
            "3. สรุปสั้นๆ 1-2 ประโยค\n"
            "ตอบเป็นภาษาไทยเท่านั้น ไม่ต้องมีคำนำหรือ disclaimer ใดๆ"
        )

    @staticmethod
    def _derive_title(request: GenerateTrainingRequest) -> str:
        tags = request.risk_score.recommended_training_tags
        if tags:
            return f"อบรมความปลอดภัยไซเบอร์: {tags[0]}"
        return "อบรมความปลอดภัยไซเบอร์เบื้องต้น"
