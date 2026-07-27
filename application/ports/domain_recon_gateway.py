from abc import ABC, abstractmethod

from domain.entities.domain_profile import DomainProfile


class DomainReconGateway(ABC):
    """
    Port สำหรับ passive reconnaissance ของ domain name (WHOIS/DNS/HTTP header)
    ห้าม implement แบบ active scan (port scan, vuln scan) — ขอบเขตนี้คือ
    รวบรวมข้อมูลสาธารณะที่เปิดเผยอยู่แล้วเพื่อ "เดา" sector ขององค์กรเท่านั้น
    """

    @abstractmethod
    async def analyze(self, domain: str) -> DomainProfile:
        raise NotImplementedError
