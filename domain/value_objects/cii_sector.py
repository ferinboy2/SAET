"""CII 7 Sectors ตาม พ.ร.บ. การรักษาความมั่นคงปลอดภัยไซเบอร์ (ประเทศไทย)"""
from enum import Enum


class CIISector(str, Enum):
    NATIONAL_SECURITY = "national_security"        # ความมั่นคงของรัฐ
    PUBLIC_SERVICE = "public_service"               # บริการภาครัฐที่สำคัญ
    FINANCE_BANKING = "finance_banking"             # การเงินการธนาคาร
    ICT_TELECOM = "ict_telecom"                     # เทคโนโลยีสารสนเทศและโทรคมนาคม
    TRANSPORT_LOGISTICS = "transport_logistics"     # การขนส่งและโลจิสติกส์
    ENERGY_UTILITIES = "energy_utilities"           # พลังงานและสาธารณูปโภค
    PUBLIC_HEALTH = "public_health"                 # สาธารณสุข

    @property
    def label_th(self) -> str:
        labels = {
            "national_security": "ความมั่นคงของรัฐ",
            "public_service": "บริการภาครัฐที่สำคัญ",
            "finance_banking": "การเงินการธนาคาร",
            "ict_telecom": "เทคโนโลยีสารสนเทศและโทรคมนาคม",
            "transport_logistics": "การขนส่งและโลจิสติกส์",
            "energy_utilities": "พลังงานและสาธารณูปโภค",
            "public_health": "สาธารณสุข",
        }
        return labels[self.value]
