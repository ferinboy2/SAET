from abc import ABC, abstractmethod

from domain.entities.domain_profile import DomainProfile
from domain.value_objects.cii_sector import CIISector


class SectorClassifier(ABC):
    """
    Port สำหรับตัดสินใจว่า DomainProfile ควรจัดอยู่ CII sector ไหน
    เปลี่ยนอัลกอริทึม (rule-based keyword matching -> ML classifier) ได้
    โดยไม่กระทบ use case ที่เรียกใช้
    """

    @abstractmethod
    def classify(self, profile: DomainProfile) -> tuple[CIISector, float]:
        """คืนค่า (sector ที่ match ดีที่สุด, confidence 0.0-1.0)"""
        raise NotImplementedError
