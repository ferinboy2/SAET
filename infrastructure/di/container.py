from functools import lru_cache

from application.ports.ai_content_generator import AIContentGenerator
from application.ports.attack_mapper import AttackMapper
from application.ports.domain_recon_gateway import DomainReconGateway
from application.ports.ioc_repository import IOCRepository
from application.ports.risk_engine import RiskEngine
from application.ports.sector_classifier import SectorClassifier
from application.ports.threat_intel_gateway import ThreatIntelGateway
from application.use_cases.assess_org_threat_relevance import (
    AssessOrgThreatRelevanceUseCase,
)
from application.use_cases.generate_training import GenerateTrainingUseCase
from application.use_cases.map_to_attack import MapToAttackUseCase
from application.use_cases.score_employee_risk import ScoreEmployeeRiskUseCase
from application.use_cases.search_ioc import SearchIOCUseCase
from config.settings import Settings
from infrastructure.ai.claude_content_generator import ClaudeContentGenerator
from infrastructure.ai.template_content_generator import TemplateContentGenerator
from infrastructure.attack.static_attack_mapper import StaticAttackMapper
from infrastructure.classification.keyword_sector_classifier import (
    KeywordSectorClassifier,
)
from infrastructure.domain_recon.mock_recon_gateway import MockDomainReconGateway
from infrastructure.domain_recon.passive_recon_gateway import PassiveDomainReconGateway
from infrastructure.persistence.in_memory_ioc_repository import InMemoryIOCRepository
from infrastructure.risk.rule_based_risk_engine import RuleBasedRiskEngine
from infrastructure.threat_intel.mock_gateway import MockThreatIntelGateway
from infrastructure.threat_intel.misp_gateway_impl import MISPGatewayImpl
from infrastructure.threat_intel.rate_limited_gateway import RateLimitedThreatIntelGateway


class Container:
    """
    DI Container — จุดเดียวที่รู้ว่า interface ไหนผูกกับ implementation ไหน

    ต้องการเปลี่ยนจาก MISP ไป threat intel provider อื่น (หรือสลับกลับไป mock
    ระหว่างพัฒนา): แก้แค่ method `threat_intel_gateway()` ที่นี่ที่เดียว
    Use case และ controller ทั้งหมดไม่ต้องแก้เลย เพราะรู้จักแค่ ThreatIntelGateway (port)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @lru_cache
    def threat_intel_gateway(self) -> ThreatIntelGateway:
        return RateLimitedThreatIntelGateway(
            wrapped=self._raw_threat_intel_gateway(),
            max_calls=self._settings.threat_intel_rate_limit_max_calls,
            window_seconds=self._settings.threat_intel_rate_limit_window_seconds,
        )

    @lru_cache
    def _raw_threat_intel_gateway(self) -> ThreatIntelGateway:
        if self._settings.threat_intel_provider == "misp":
            return MISPGatewayImpl(
                base_url=self._settings.misp_base_url,
                api_key=self._settings.misp_api_key,
                timeout=self._settings.misp_timeout_seconds,
            )
        # ค่า default = mock เพื่อให้ dev ทำงานต่อได้โดยไม่ต้องมี MISP instance จริง
        return MockThreatIntelGateway()

    @lru_cache
    def ioc_repository(self) -> IOCRepository:
        return InMemoryIOCRepository()

    @lru_cache
    def domain_recon_gateway(self) -> DomainReconGateway:
        if self._settings.domain_recon_provider == "passive":
            return PassiveDomainReconGateway()
        # ค่า default = mock เพื่อพัฒนา/ทดสอบโดยไม่ต้องมี network egress ไป WHOIS/DNS จริง
        return MockDomainReconGateway()

    @lru_cache
    def sector_classifier(self) -> SectorClassifier:
        return KeywordSectorClassifier()

    @lru_cache
    def attack_mapper(self) -> AttackMapper:
        return StaticAttackMapper()

    @lru_cache
    def risk_engine(self) -> RiskEngine:
        return RuleBasedRiskEngine()

    @lru_cache
    def ai_content_generator(self) -> AIContentGenerator:
        # ใช้ Claude เป็น primary เสมอ — ถ้าไม่มี api_key มันจะ raise AIGenerationError
        # ทันที (เช็คใน ClaudeContentGenerator.generate) แล้ว use case จะ fallback ไป
        # template โดยอัตโนมัติ พร้อม label ผลลัพธ์ว่า "template" อย่างถูกต้อง
        return ClaudeContentGenerator(
            api_key=self._settings.anthropic_api_key,
            model=self._settings.anthropic_model,
        )

    @lru_cache
    def ai_content_generator_fallback(self) -> AIContentGenerator:
        return TemplateContentGenerator()

    def search_ioc_use_case(self) -> SearchIOCUseCase:
        return SearchIOCUseCase(
            gateway=self.threat_intel_gateway(),
            cache_repo=self.ioc_repository(),
        )

    def assess_org_threat_relevance_use_case(self) -> AssessOrgThreatRelevanceUseCase:
        return AssessOrgThreatRelevanceUseCase(
            gateway=self.threat_intel_gateway(),
            domain_recon=self.domain_recon_gateway(),
            sector_classifier=self.sector_classifier(),
        )

    def map_to_attack_use_case(self) -> MapToAttackUseCase:
        return MapToAttackUseCase(mapper=self.attack_mapper())

    def score_employee_risk_use_case(self) -> ScoreEmployeeRiskUseCase:
        return ScoreEmployeeRiskUseCase(
            risk_engine=self.risk_engine(),
            gateway=self.threat_intel_gateway(),
        )

    def generate_training_use_case(self) -> GenerateTrainingUseCase:
        return GenerateTrainingUseCase(
            ai_generator=self.ai_content_generator(),
            fallback_generator=self.ai_content_generator_fallback(),
        )


@lru_cache
def get_container() -> Container:
    return Container(settings=Settings())
