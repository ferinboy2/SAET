from dataclasses import dataclass, field
from enum import Enum


class AccessLevel(str, Enum):
    STANDARD = "standard"
    PRIVILEGED = "privileged"      # admin, DBA, domain admin ฯลฯ
    EXECUTIVE = "executive"        # C-level, มักโดน BEC/spear-phishing


@dataclass(frozen=True, slots=True)
class Employee:
    id: str
    name: str
    department: str
    access_level: AccessLevel = AccessLevel.STANDARD
    email: str | None = None
    # ผลจาก phishing simulation ล่าสุด และการอบรมที่ผ่าน/ยังไม่ผ่าน
    recent_phishing_click_rate: float = 0.0     # 0.0 - 1.0
    completed_trainings: list[str] = field(default_factory=list)
