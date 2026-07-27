from abc import ABC, abstractmethod


class AIContentGenerator(ABC):
    """
    Port กลางสำหรับ AI text generation provider ใดๆ (Claude, หรือ LLM อื่น)
    เป็น generic text generation ล้วนๆ — prompt engineering (การเลือกใช้คำ,
    โครงสร้างเนื้อหา) เป็นหน้าที่ของ use case ไม่ใช่ของ port นี้
    เพื่อให้เปลี่ยน AI provider ได้โดยไม่กระทบ business logic ที่ควบคุมเนื้อหา
    """

    @abstractmethod
    async def generate(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1000
    ) -> str:
        raise NotImplementedError
