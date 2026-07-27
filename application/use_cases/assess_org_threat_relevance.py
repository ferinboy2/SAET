"""Phase 3: จับคู่ Threat <-> องค์กร ตาม CII Sector หรือ Domain name"""
from dataclasses import dataclass, field

from application.ports.domain_recon_gateway import DomainReconGateway
from application.ports.sector_classifier import SectorClassifier
from application.ports.threat_intel_gateway import ThreatIntelGateway
from domain.entities.threat import ThreatEvent
from domain.value_objects.cii_sector import CIISector


@dataclass(slots=True)
class AssessOrgThreatRelevanceRequest:
    sector: CIISector | None = None
    domain: str | None = None  # ระบุอย่างใดอย่างหนึ่ง sector หรือ domain

    def __post_init__(self) -> None:
        if self.sector is None and self.domain is None:
            raise ValueError("ต้องระบุ sector หรือ domain อย่างน้อยหนึ่งอย่าง")


@dataclass(slots=True)
class AssessOrgThreatRelevanceResponse:
    matched_sector: CIISector
    sector_confidence: float  # 1.0 ถ้าผู้ใช้ระบุ sector เอง, <1.0 ถ้ามาจากการเดาจาก domain
    relevant_threats: list[ThreatEvent] = field(default_factory=list)


class AssessOrgThreatRelevanceUseCase:
    """
    ถ้าผู้ใช้ระบุ sector มาตรงๆ -> ใช้เลย confidence = 1.0
    ถ้าระบุ domain -> เรียก DomainReconGateway (passive) แล้วส่งต่อให้ SectorClassifier
    เพื่อเดา sector ที่ใกล้เคียงที่สุด จากนั้นดึง threat event ของ sector นั้นจาก ThreatIntelGateway

    หมายเหตุ: domain_recon และ sector_classifier เป็น optional เพราะ path ที่ระบุ
    sector ตรงๆ ไม่จำเป็นต้องใช้ทั้งสอง — แต่ต้องมีค่าถ้า request.domain ถูกใช้งาน
    """

    def __init__(
        self,
        gateway: ThreatIntelGateway,
        domain_recon: DomainReconGateway | None = None,
        sector_classifier: SectorClassifier | None = None,
    ) -> None:
        self._gateway = gateway
        self._domain_recon = domain_recon
        self._sector_classifier = sector_classifier

    async def execute(
        self, request: AssessOrgThreatRelevanceRequest
    ) -> AssessOrgThreatRelevanceResponse:
        if request.sector is not None:
            sector = request.sector
            confidence = 1.0
        else:
            if self._domain_recon is None or self._sector_classifier is None:
                raise ValueError(
                    "ต้องมี domain_recon และ sector_classifier เพื่อวิเคราะห์จาก domain name"
                )
            profile = await self._domain_recon.analyze(request.domain)  # type: ignore[arg-type]
            sector, confidence = self._sector_classifier.classify(profile)

        threats = await self._gateway.get_events_by_sector(sector.value)

        return AssessOrgThreatRelevanceResponse(
            matched_sector=sector,
            sector_confidence=confidence,
            relevant_threats=threats,
        )
