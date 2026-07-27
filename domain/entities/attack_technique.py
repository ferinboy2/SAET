from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """MITRE ATT&CK Technique พร้อมคำแนะนำ Prevent/Detect/Respond"""

    technique_id: str          # เช่น "T1566"
    name: str                  # เช่น "Phishing"
    tactic: str                # เช่น "Initial Access"
    prevent_guidance: list[str] = field(default_factory=list)
    detect_guidance: list[str] = field(default_factory=list)
    respond_guidance: list[str] = field(default_factory=list)
