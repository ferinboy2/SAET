import pytest

from application.use_cases.assess_org_threat_relevance import (
    AssessOrgThreatRelevanceRequest,
    AssessOrgThreatRelevanceUseCase,
)
from domain.value_objects.cii_sector import CIISector
from infrastructure.classification.keyword_sector_classifier import (
    KeywordSectorClassifier,
)
from infrastructure.domain_recon.mock_recon_gateway import MockDomainReconGateway
from infrastructure.threat_intel.mock_gateway import MockThreatIntelGateway


@pytest.mark.asyncio
async def test_assess_with_explicit_sector_uses_full_confidence():
    gateway = MockThreatIntelGateway()
    use_case = AssessOrgThreatRelevanceUseCase(gateway=gateway)

    response = await use_case.execute(
        AssessOrgThreatRelevanceRequest(sector=CIISector.FINANCE_BANKING)
    )

    assert response.matched_sector == CIISector.FINANCE_BANKING
    assert response.sector_confidence == 1.0
    assert len(response.relevant_threats) == 1
    assert response.relevant_threats[0].id == "evt-001"


@pytest.mark.asyncio
async def test_assess_with_bank_domain_classifies_finance_banking():
    gateway = MockThreatIntelGateway()
    recon = MockDomainReconGateway()
    classifier = KeywordSectorClassifier()
    use_case = AssessOrgThreatRelevanceUseCase(
        gateway=gateway, domain_recon=recon, sector_classifier=classifier
    )

    response = await use_case.execute(
        AssessOrgThreatRelevanceRequest(domain="examplebank.co.th")
    )

    assert response.matched_sector == CIISector.FINANCE_BANKING
    assert response.sector_confidence > 0.3
    assert len(response.relevant_threats) == 1


@pytest.mark.asyncio
async def test_assess_with_go_th_domain_classifies_public_service_via_tld():
    gateway = MockThreatIntelGateway()
    recon = MockDomainReconGateway()
    classifier = KeywordSectorClassifier()
    use_case = AssessOrgThreatRelevanceUseCase(
        gateway=gateway, domain_recon=recon, sector_classifier=classifier
    )

    response = await use_case.execute(
        AssessOrgThreatRelevanceRequest(domain="exampleagency.go.th")
    )

    assert response.matched_sector == CIISector.PUBLIC_SERVICE
    assert response.sector_confidence == 0.9  # strong TLD signal
    assert len(response.relevant_threats) == 1
    assert response.relevant_threats[0].id == "evt-002"


@pytest.mark.asyncio
async def test_assess_with_unknown_domain_falls_back_to_default_sector():
    gateway = MockThreatIntelGateway()
    recon = MockDomainReconGateway()
    classifier = KeywordSectorClassifier()
    use_case = AssessOrgThreatRelevanceUseCase(
        gateway=gateway, domain_recon=recon, sector_classifier=classifier
    )

    response = await use_case.execute(
        AssessOrgThreatRelevanceRequest(domain="totally-unknown-xyz.com")
    )

    assert response.matched_sector == CIISector.ICT_TELECOM
    assert response.sector_confidence == 0.15


def test_request_raises_when_neither_sector_nor_domain_given():
    with pytest.raises(ValueError):
        AssessOrgThreatRelevanceRequest()


@pytest.mark.asyncio
async def test_domain_request_without_recon_dependencies_raises():
    gateway = MockThreatIntelGateway()
    use_case = AssessOrgThreatRelevanceUseCase(gateway=gateway)  # no recon/classifier

    with pytest.raises(ValueError):
        await use_case.execute(AssessOrgThreatRelevanceRequest(domain="example.com"))
