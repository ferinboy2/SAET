from datetime import datetime, timezone

import pytest

from application.use_cases.generate_training import (
    GenerateTrainingRequest,
    GenerateTrainingUseCase,
)
from domain.entities.risk_score import RiskScore, RiskScoreBreakdown
from domain.exceptions import AIGenerationError
from infrastructure.ai.mock_content_generator import MockAIContentGenerator
from infrastructure.ai.template_content_generator import TemplateContentGenerator


def _make_risk_score(level_tags: list[str] | None = None, total: float = 60.0) -> RiskScore:
    tags = ["Phishing", "Valid Accounts"] if level_tags is None else level_tags
    return RiskScore(
        employee_id="emp-1",
        total_score=total,
        breakdown=RiskScoreBreakdown(exposure=70, behavior=60, threat_landscape=50),
        calculated_at=datetime.now(timezone.utc),
        recommended_training_tags=tags,
    )


@pytest.mark.asyncio
async def test_generate_training_uses_primary_ai_generator_when_healthy():
    ai = MockAIContentGenerator(canned_response="เนื้อหาจริงจาก AI")
    use_case = GenerateTrainingUseCase(ai_generator=ai)

    response = await use_case.execute(
        GenerateTrainingRequest(risk_score=_make_risk_score(), employee_department="Finance")
    )

    assert response.generated_by == "ai"
    assert response.content_th == "เนื้อหาจริงจาก AI"
    assert response.priority == "high"  # total_score=60 -> level high
    assert "Phishing" in response.title_th


@pytest.mark.asyncio
async def test_generate_training_falls_back_to_template_when_ai_fails():
    ai = MockAIContentGenerator(simulate_failure=True)
    fallback = TemplateContentGenerator()
    use_case = GenerateTrainingUseCase(ai_generator=ai, fallback_generator=fallback)

    response = await use_case.execute(
        GenerateTrainingRequest(risk_score=_make_risk_score(), employee_department="Finance")
    )

    assert response.generated_by == "template"
    assert "template" in response.content_th.lower()


@pytest.mark.asyncio
async def test_generate_training_raises_when_ai_fails_and_no_fallback():
    ai = MockAIContentGenerator(simulate_failure=True)
    use_case = GenerateTrainingUseCase(ai_generator=ai, fallback_generator=None)

    with pytest.raises(AIGenerationError):
        await use_case.execute(GenerateTrainingRequest(risk_score=_make_risk_score()))


@pytest.mark.asyncio
async def test_generate_training_prompt_includes_recommended_tags_and_department():
    ai = MockAIContentGenerator()
    use_case = GenerateTrainingUseCase(ai_generator=ai)

    await use_case.execute(
        GenerateTrainingRequest(
            risk_score=_make_risk_score(level_tags=["Ransomware Awareness"]),
            employee_department="HR",
        )
    )

    assert "Ransomware Awareness" in ai.last_user_prompt
    assert "HR" in ai.last_user_prompt


@pytest.mark.asyncio
async def test_generate_training_title_falls_back_when_no_tags():
    ai = MockAIContentGenerator()
    use_case = GenerateTrainingUseCase(ai_generator=ai)

    response = await use_case.execute(
        GenerateTrainingRequest(risk_score=_make_risk_score(level_tags=[]))
    )

    assert response.title_th == "อบรมความปลอดภัยไซเบอร์เบื้องต้น"
