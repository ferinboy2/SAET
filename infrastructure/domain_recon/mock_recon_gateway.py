from application.ports.domain_recon_gateway import DomainReconGateway
from domain.entities.domain_profile import DomainProfile


class MockDomainReconGateway(DomainReconGateway):
    """
    Domain recon จำลอง สำหรับ dev/test โดยไม่ต้องยิง network จริง
    ข้อมูลอิงจาก dictionary คงที่ — เพิ่ม entry ใหม่ได้ตามต้องการระหว่างพัฒนา
    """

    def __init__(self) -> None:
        self._known_profiles: dict[str, DomainProfile] = {
            "examplebank.co.th": DomainProfile(
                domain="examplebank.co.th",
                tld="co.th",
                registrant_org="Example Bank Public Company Limited",
                mx_providers=["google"],
                tech_signals=["cloudflare", "react"],
                page_title="Example Bank - ธนาคารตัวอย่าง",
                keywords=["bank", "ธนาคาร", "finance", "การเงิน"],
            ),
            "exampleagency.go.th": DomainProfile(
                domain="exampleagency.go.th",
                tld="go.th",
                registrant_org="Example Government Agency",
                mx_providers=["on-premise"],
                tech_signals=["apache"],
                page_title="หน่วยงานราชการตัวอย่าง",
                keywords=["government", "ราชการ", "กระทรวง"],
            ),
        }

    async def analyze(self, domain: str) -> DomainProfile:
        if domain in self._known_profiles:
            return self._known_profiles[domain]
        # ไม่รู้จัก domain นี้ -> คืน profile ว่างเปล่า (นอกจาก tld ที่แยกได้จากชื่อ)
        tld = domain.split(".", 1)[1] if "." in domain else None
        return DomainProfile(domain=domain, tld=tld)
