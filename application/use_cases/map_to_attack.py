"""Phase 4: แปลง ThreatEvent -> MITRE ATT&CK Technique พร้อมคำแนะนำ Prevent/Detect/Respond"""
from dataclasses import dataclass

from application.ports.attack_mapper import AttackMapper
from domain.entities.attack_technique import AttackTechnique
from domain.entities.threat import ThreatEvent


@dataclass(slots=True)
class MapToAttackRequest:
    threat: ThreatEvent


class MapToAttackUseCase:
    def __init__(self, mapper: AttackMapper) -> None:
        self._mapper = mapper

    def execute(self, request: MapToAttackRequest) -> list[AttackTechnique]:
        return self._mapper.map_threat(request.threat)
