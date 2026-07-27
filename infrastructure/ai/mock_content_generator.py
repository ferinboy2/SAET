from application.ports.ai_content_generator import AIContentGenerator
from domain.exceptions import AIGenerationError


class MockAIContentGenerator(AIContentGenerator):
    """Mock สำหรับ dev/test — ไม่เรียก network จริง จำลอง success หรือ failure ได้"""

    def __init__(self, simulate_failure: bool = False, canned_response: str = "เนื้อหา training ตัวอย่าง") -> None:
        self._simulate_failure = simulate_failure
        self._canned_response = canned_response
        self.last_system_prompt: str | None = None
        self.last_user_prompt: str | None = None

    async def generate(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1000
    ) -> str:
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        if self._simulate_failure:
            raise AIGenerationError("Simulated AI generation failure for testing")
        return self._canned_response
