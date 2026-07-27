import logging

from application.ports.attack_mapper import AttackMapper
from domain.entities.attack_technique import AttackTechnique
from domain.entities.threat import ThreatEvent
from domain.exceptions import AttackMappingError
from infrastructure.attack.attack_technique_catalog import lookup_technique

logger = logging.getLogger(__name__)


class StaticAttackMapper(AttackMapper):
    """
    Implementation ของ AttackMapper ที่ใช้ catalog แบบ static (in-memory dict)
    เปลี่ยนไปใช้ MITRE ATT&CK STIX bundle เต็มรูปแบบในอนาคตได้ โดยเขียน mapper ใหม่
    implement interface เดียวกันนี้ ไม่ต้องแก้ use case หรือ controller
    """

    def map_threat(self, threat: ThreatEvent) -> list[AttackTechnique]:
        if not threat.ttp_ids:
            raise AttackMappingError(
                f"Threat '{threat.id}' ไม่มี ttp_ids ให้ map เป็น ATT&CK technique"
            )

        techniques: list[AttackTechnique] = []
        seen_ids: set[str] = set()

        for ttp_id in threat.ttp_ids:
            technique = lookup_technique(ttp_id)
            if technique is None:
                logger.warning(
                    "ไม่พบ technique '%s' ใน catalog สำหรับ threat '%s'",
                    ttp_id,
                    threat.id,
                )
                continue
            if technique.technique_id not in seen_ids:
                techniques.append(technique)
                seen_ids.add(technique.technique_id)

        return techniques
