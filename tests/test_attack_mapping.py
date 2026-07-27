from datetime import datetime

import pytest

from application.use_cases.map_to_attack import MapToAttackRequest, MapToAttackUseCase
from domain.entities.threat import ThreatEvent
from domain.exceptions import AttackMappingError
from infrastructure.attack.attack_technique_catalog import lookup_technique
from infrastructure.attack.static_attack_mapper import StaticAttackMapper


def _make_threat(ttp_ids: list[str]) -> ThreatEvent:
    return ThreatEvent(
        id="evt-test",
        title="Test threat",
        source="TEST",
        published=datetime(2026, 7, 1),
        ttp_ids=ttp_ids,
    )


def test_lookup_technique_direct_match():
    technique = lookup_technique("T1078")
    assert technique is not None
    assert technique.name == "Valid Accounts"


def test_lookup_technique_falls_back_to_parent_for_subtechnique():
    # T1566.002 ไม่ได้ define ตรงๆ แยกจาก T1566 ใน catalog ตรวจว่า fallback ทำงาน
    technique = lookup_technique("T1566.999")  # sub-technique ที่ไม่มีจริง
    assert technique is not None
    assert technique.technique_id == "T1566"


def test_lookup_technique_returns_none_for_unknown_id():
    assert lookup_technique("T9999") is None


def test_static_attack_mapper_maps_known_ttps():
    mapper = StaticAttackMapper()
    threat = _make_threat(["T1566.002", "T1078"])

    techniques = mapper.map_threat(threat)

    ids = {t.technique_id for t in techniques}
    assert "T1566.002" in ids
    assert "T1078" in ids


def test_static_attack_mapper_skips_unknown_ttp_without_raising():
    mapper = StaticAttackMapper()
    threat = _make_threat(["T1078", "T9999-unknown"])

    techniques = mapper.map_threat(threat)

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1078"


def test_static_attack_mapper_raises_when_no_ttp_ids():
    mapper = StaticAttackMapper()
    threat = _make_threat([])

    with pytest.raises(AttackMappingError):
        mapper.map_threat(threat)


def test_static_attack_mapper_deduplicates_same_parent_technique():
    mapper = StaticAttackMapper()
    # ทั้งสอง sub-technique ไม่มีตรงๆ ใน catalog -> fallback ไป parent เดียวกัน (T1566) ไม่ควรซ้ำ
    threat = _make_threat(["T1566.001", "T1566.003"])

    techniques = mapper.map_threat(threat)

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1566"


def test_map_to_attack_use_case_delegates_to_mapper():
    mapper = StaticAttackMapper()
    use_case = MapToAttackUseCase(mapper=mapper)
    threat = _make_threat(["T1486"])

    techniques = use_case.execute(MapToAttackRequest(threat=threat))

    assert len(techniques) == 1
    assert techniques[0].name == "Data Encrypted for Impact"
    assert "backup" in techniques[0].prevent_guidance[0].lower()
