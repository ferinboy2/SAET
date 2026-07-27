from datetime import datetime

import pytest

from application.use_cases.score_employee_risk import (
    ScoreEmployeeRiskRequest,
    ScoreEmployeeRiskUseCase,
)
from domain.entities.employee import AccessLevel, Employee
from domain.entities.threat import ThreatEvent
from domain.value_objects.cii_sector import CIISector
from infrastructure.risk.rule_based_risk_engine import RuleBasedRiskEngine
from infrastructure.threat_intel.mock_gateway import MockThreatIntelGateway


def _make_employee(**overrides) -> Employee:
    defaults = dict(
        id="emp-1",
        name="Somchai",
        department="IT",
        access_level=AccessLevel.STANDARD,
        recent_phishing_click_rate=0.0,
        completed_trainings=[],
    )
    defaults.update(overrides)
    return Employee(**defaults)


def _make_threat(ttp_ids: list[str]) -> ThreatEvent:
    return ThreatEvent(
        id="evt-x",
        title="Test",
        source="TEST",
        published=datetime(2026, 7, 1),
        ttp_ids=ttp_ids,
    )


@pytest.mark.asyncio
async def test_privileged_high_click_rate_scores_higher_than_standard_low_click_rate():
    engine = RuleBasedRiskEngine()

    low_risk_employee = _make_employee(
        access_level=AccessLevel.STANDARD, recent_phishing_click_rate=0.0
    )
    high_risk_employee = _make_employee(
        access_level=AccessLevel.EXECUTIVE, recent_phishing_click_rate=0.8
    )

    low_score = await engine.calculate(low_risk_employee, active_threats=[])
    high_score = await engine.calculate(high_risk_employee, active_threats=[])

    assert high_score.total_score > low_score.total_score
    assert low_score.level in ("low", "medium")
    assert high_score.level in ("high", "critical")


@pytest.mark.asyncio
async def test_completed_trainings_reduce_behavior_score():
    engine = RuleBasedRiskEngine()
    employee_no_training = _make_employee(recent_phishing_click_rate=0.5)
    employee_trained = _make_employee(
        recent_phishing_click_rate=0.5,
        completed_trainings=["Phishing", "Valid Accounts"],
    )

    score_no_training = await engine.calculate(employee_no_training, active_threats=[])
    score_trained = await engine.calculate(employee_trained, active_threats=[])

    assert score_trained.breakdown.behavior < score_no_training.breakdown.behavior


@pytest.mark.asyncio
async def test_more_active_threats_increase_threat_landscape_score():
    engine = RuleBasedRiskEngine()
    employee = _make_employee()

    score_no_threats = await engine.calculate(employee, active_threats=[])
    score_with_threats = await engine.calculate(
        employee, active_threats=[_make_threat(["T1566"]), _make_threat(["T1078"])]
    )

    assert score_with_threats.breakdown.threat_landscape > score_no_threats.breakdown.threat_landscape


@pytest.mark.asyncio
async def test_recommended_training_tags_exclude_already_completed():
    engine = RuleBasedRiskEngine()
    employee = _make_employee(completed_trainings=["Phishing"])
    threats = [_make_threat(["T1566", "T1078"])]

    score = await engine.calculate(employee, active_threats=threats)

    assert "Phishing" not in score.recommended_training_tags
    assert "Valid Accounts" in score.recommended_training_tags


@pytest.mark.asyncio
async def test_score_employee_risk_use_case_fetches_threats_and_delegates_to_engine():
    gateway = MockThreatIntelGateway()
    engine = RuleBasedRiskEngine()
    use_case = ScoreEmployeeRiskUseCase(risk_engine=engine, gateway=gateway)
    employee = _make_employee(access_level=AccessLevel.PRIVILEGED)

    risk_score = await use_case.execute(
        ScoreEmployeeRiskRequest(employee=employee, sector=CIISector.FINANCE_BANKING)
    )

    assert risk_score.employee_id == "emp-1"
    assert risk_score.breakdown.threat_landscape > 10.0  # มี mock threat ใน finance_banking
