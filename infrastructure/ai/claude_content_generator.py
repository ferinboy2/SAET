import httpx

from application.ports.ai_content_generator import AIContentGenerator
from domain.exceptions import AIGenerationError

_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class ClaudeContentGenerator(AIContentGenerator):
    """
    Adapter เฉพาะของ Claude API — ความรู้เรื่อง Anthropic Messages API ทั้งหมด
    อยู่ในไฟล์นี้ไฟล์เดียว ถ้าจะเปลี่ยนไปใช้ LLM provider อื่นในอนาคต เขียนคลาสใหม่
    implement AIContentGenerator แทนที่นี่ได้เลย ไม่กระทบ use case ที่เรียกใช้

    ใช้ model ที่ประหยัด token (Sonnet) เป็นค่า default เพราะงาน generate เนื้อหา
    training ไม่จำเป็นต้องใช้ model ระดับ Opus — ดูแนวทางเลือก model ใน
    SAET_Project_Plan.md ส่วนกลยุทธ์ประหยัด token
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-5",
        timeout: float = 30.0,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    async def generate(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1000
    ) -> str:
        if not self._api_key:
            raise AIGenerationError("ANTHROPIC_API_KEY ไม่ได้ตั้งค่า")

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _API_VERSION,
            "content-type": "application/json",
        }
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(_API_URL, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise AIGenerationError("Claude API request timed out") from exc
        except httpx.RequestError as exc:
            raise AIGenerationError(f"Claude API connection failed: {exc}") from exc

        if resp.status_code == 401:
            raise AIGenerationError("Claude API key invalid or expired")
        if resp.status_code == 429:
            raise AIGenerationError("Claude API rate limited")
        if resp.status_code >= 500:
            raise AIGenerationError(f"Claude API server error: {resp.status_code}")
        if resp.status_code >= 400:
            raise AIGenerationError(f"Claude API request error: {resp.status_code} {resp.text}")

        data = resp.json()
        text_blocks = [
            block["text"] for block in data.get("content", []) if block.get("type") == "text"
        ]
        if not text_blocks:
            raise AIGenerationError("Claude API returned no text content")
        return "\n".join(text_blocks)
