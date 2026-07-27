from application.ports.ai_content_generator import AIContentGenerator

_FALLBACK_TEMPLATE = (
    "[เนื้อหานี้สร้างจาก template สำรอง เนื่องจาก AI service ไม่พร้อมใช้งานชั่วคราว]\n\n"
    "ข้อควรระวังทั่วไปด้านความปลอดภัยไซเบอร์:\n"
    "- ตรวจสอบผู้ส่งอีเมลก่อนคลิกลิงก์หรือเปิดไฟล์แนบทุกครั้ง\n"
    "- ห้ามเปิดเผยรหัสผ่านหรือรหัส OTP ให้ผู้อื่นไม่ว่ากรณีใด\n"
    "- หากพบสิ่งผิดปกติ (อีเมลแปลก, ระบบทำงานช้าผิดปกติ, ไฟล์ที่เข้าไม่ได้) "
    "ให้แจ้งทีมความปลอดภัยทันที\n"
    "- ใช้รหัสผ่านที่คาดเดายากและเปิดใช้ multi-factor authentication ทุกระบบที่รองรับ"
)


class TemplateContentGenerator(AIContentGenerator):
    """
    Fallback generator แบบ deterministic ไม่พึ่งพา AI/network ใดๆ
    ใช้เมื่อ Claude API ใช้งานไม่ได้ (rate limit, key หมดอายุ, network ล่ม)
    เพื่อให้ผู้ใช้ยังได้เนื้อหา awareness พื้นฐานแทนที่จะได้ error เปล่าๆ
    """

    async def generate(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1000
    ) -> str:
        return _FALLBACK_TEMPLATE
