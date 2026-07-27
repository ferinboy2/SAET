class SAETError(Exception):
    """Base exception ของทั้งระบบ"""


# --- Threat Intel (MISP หรือ provider อื่น) ---
class ThreatIntelError(SAETError):
    """Base exception สำหรับทุก error ที่มาจาก Threat Intel Gateway"""


class ThreatIntelUnavailableError(ThreatIntelError):
    """Provider ล่ม/timeout — use case ควร fallback ไป cache หรือแจ้ง degraded mode"""


class ThreatIntelAuthError(ThreatIntelError):
    """API key ผิด/หมดอายุ"""


class ThreatIntelRateLimitError(ThreatIntelUnavailableError):
    """
    โดน rate limit จาก provider (หรือจาก rate limiter ฝั่งเราเองที่กันไม่ให้ยิง MISP ถี่เกินไป)
    เป็น subtype ของ ThreatIntelUnavailableError โดยตั้งใจ — เพื่อให้ use case ที่ catch
    ThreatIntelUnavailableError (เช่น SearchIOCUseCase) fallback ไป cache ได้อัตโนมัติ
    โดยไม่ต้องรู้จัก exception type นี้เป็นการเฉพาะ
    """


# --- Risk Engine ---
class RiskEngineError(SAETError):
    """Base exception ของ Risk Engine"""


class InsufficientDataError(RiskEngineError):
    """ข้อมูลไม่พอสำหรับคำนวณ risk score (เช่น employee ใหม่ ยังไม่มี phishing sim history)"""


# --- ATT&CK Mapping ---
class AttackMappingError(SAETError):
    """ไม่สามารถ map threat ไป technique ได้ (เช่น ไม่มี ttp_ids ในข้อมูล)"""


# --- AI Content Generation ---
class AIGenerationError(SAETError):
    """เรียก AI content generator (เช่น Claude API) ไม่สำเร็จ — ควร fallback ไป template"""


# --- Sector / Domain matching ---
class UnknownSectorError(SAETError):
    """ระบุ sector ที่ไม่อยู่ใน CII 7 sectors"""


class DomainReconError(SAETError):
    """Passive recon จาก domain name ล้มเหลว (DNS/WHOIS/HTTP ไม่สำเร็จ)"""
