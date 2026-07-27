from abc import ABC, abstractmethod

from domain.entities.attack_technique import AttackTechnique
from domain.entities.threat import ThreatEvent


class AttackMapper(ABC):
    """Port สำหรับ map threat/IOC -> MITRE ATT&CK Technique พร้อมคำแนะนำ Prevent/Detect/Respond"""

    @abstractmethod
    def map_threat(self, threat: ThreatEvent) -> list[AttackTechnique]:
        raise NotImplementedError
