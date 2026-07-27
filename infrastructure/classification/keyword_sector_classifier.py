from application.ports.sector_classifier import SectorClassifier
from domain.entities.domain_profile import DomainProfile
from domain.value_objects.cii_sector import CIISector

# คำสำคัญ (ไทย/อังกฤษ) ต่อ CII sector — ปรับ/เพิ่มได้ตามข้อมูลจริงที่เจอ
_SECTOR_KEYWORDS: dict[CIISector, set[str]] = {
    CIISector.FINANCE_BANKING: {
        "bank", "ธนาคาร", "finance", "การเงิน", "insurance", "ประกัน",
        "securities", "หลักทรัพย์", "payment", "ชำระเงิน",
    },
    CIISector.ENERGY_UTILITIES: {
        "energy", "พลังงาน", "electric", "ไฟฟ้า", "power", "gas", "แก๊ส",
        "water", "ประปา", "utility", "สาธารณูปโภค",
    },
    CIISector.ICT_TELECOM: {
        "telecom", "โทรคมนาคม", "network", "เครือข่าย", "cloud", "data",
        "internet", "isp", "software", "digital", "ดิจิทัล",
    },
    CIISector.TRANSPORT_LOGISTICS: {
        "airline", "สายการบิน", "airport", "สนามบิน", "logistics",
        "โลจิสติกส์", "transport", "ขนส่ง", "railway", "รถไฟ", "port", "ท่าเรือ",
    },
    CIISector.PUBLIC_HEALTH: {
        "hospital", "โรงพยาบาล", "health", "สุขภาพ", "clinic", "คลินิก",
        "medical", "การแพทย์", "สาธารณสุข",
    },
    CIISector.PUBLIC_SERVICE: {
        "government", "รัฐบาล", "ministry", "กระทรวง", "department", "กรม",
        "agency", "หน่วยงาน", "ราชการ", "municipality", "เทศบาล",
    },
    CIISector.NATIONAL_SECURITY: {
        "military", "ทหาร", "defense", "defence", "กลาโหม", "security",
        "ความมั่นคง", "police", "ตำรวจ",
    },
}

# TLD ที่เป็นสัญญาณแรงสำหรับบาง sector
_TLD_HINTS: dict[str, CIISector] = {
    "go.th": CIISector.PUBLIC_SERVICE,
    "mi.th": CIISector.NATIONAL_SECURITY,
    "ac.th": CIISector.PUBLIC_SERVICE,  # หน่วยงานการศึกษาของรัฐ ใกล้เคียง public service
}

_DEFAULT_SECTOR = CIISector.ICT_TELECOM  # แทบทุกองค์กรมี IT footprint อย่างน้อยที่สุด
_DEFAULT_CONFIDENCE = 0.15


class KeywordSectorClassifier(SectorClassifier):
    """
    Rule-based classifier: ให้คะแนนแต่ละ sector จากจำนวน keyword ที่ match
    กับ registrant_org / page_title / tld แล้วเลือก sector ที่คะแนนสูงสุด
    ถ้าไม่มี keyword ตรงเลย fallback เป็น ICT_TELECOM ด้วย confidence ต่ำ
    """

    def classify(self, profile: DomainProfile) -> tuple[CIISector, float]:
        if profile.tld and profile.tld in _TLD_HINTS:
            return _TLD_HINTS[profile.tld], 0.9

        haystack = " ".join(profile.keywords).lower()
        if profile.page_title:
            haystack += " " + profile.page_title.lower()
        if not haystack.strip():
            return _DEFAULT_SECTOR, _DEFAULT_CONFIDENCE

        scores: dict[CIISector, int] = {}
        for sector, keywords in _SECTOR_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in haystack)
            if score > 0:
                scores[sector] = score

        if not scores:
            return _DEFAULT_SECTOR, _DEFAULT_CONFIDENCE

        best_sector = max(scores, key=lambda s: scores[s])
        max_possible = len(_SECTOR_KEYWORDS[best_sector])
        confidence = min(1.0, scores[best_sector] / max_possible)
        return best_sector, confidence
