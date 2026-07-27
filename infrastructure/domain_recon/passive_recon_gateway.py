import re

import dns.asyncresolver
import httpx
import whois  # python-whois

from application.ports.domain_recon_gateway import DomainReconGateway
from domain.entities.domain_profile import DomainProfile
from domain.exceptions import DomainReconError

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WORD_RE = re.compile(r"[a-zA-Zก-๙]{3,}")


class PassiveDomainReconGateway(DomainReconGateway):
    """
    Passive recon เท่านั้น: WHOIS, MX record, และ GET หน้าแรกเพื่ออ่าน header/title
    ไม่มีการ scan port หรือ probe endpoint ใดๆ ที่นอกเหนือจากหน้าแรกสาธารณะ

    หมายเหตุ: ต้องมี network egress ไปยัง DNS/WHOIS/เว็บไซต์เป้าหมายจึงจะทำงานได้จริง
    ใน environment ที่ปิด egress (เช่น sandbox พัฒนา) ให้ใช้ MockDomainReconGateway แทน
    """

    def __init__(self, http_timeout: float = 8.0) -> None:
        self._http_timeout = http_timeout

    async def analyze(self, domain: str) -> DomainProfile:
        tld = domain.split(".", 1)[1] if "." in domain else None

        registrant_org = await self._safe_whois_org(domain)
        mx_providers = await self._safe_mx_lookup(domain)
        page_title, tech_signals = await self._safe_fetch_homepage(domain)

        keywords = self._extract_keywords(registrant_org, page_title)

        return DomainProfile(
            domain=domain,
            tld=tld,
            registrant_org=registrant_org,
            mx_providers=mx_providers,
            tech_signals=tech_signals,
            page_title=page_title,
            keywords=keywords,
        )

    async def _safe_whois_org(self, domain: str) -> str | None:
        try:
            w = whois.whois(domain)
        except Exception as exc:  # WHOIS library ไม่มี typed exception ที่แน่นอน
            raise DomainReconError(f"WHOIS lookup failed for {domain}: {exc}") from exc
        org = getattr(w, "org", None)
        if isinstance(org, list):
            return org[0] if org else None
        return org

    async def _safe_mx_lookup(self, domain: str) -> list[str]:
        try:
            answers = await dns.asyncresolver.resolve(domain, "MX")
        except Exception:
            return []  # ไม่มี MX record ไม่ถือเป็น error ร้ายแรง
        providers = []
        for rdata in answers:
            exchange = str(rdata.exchange).lower()
            if "google" in exchange:
                providers.append("google")
            elif "outlook" in exchange or "microsoft" in exchange:
                providers.append("microsoft")
            else:
                providers.append(exchange)
        return providers

    async def _safe_fetch_homepage(self, domain: str) -> tuple[str | None, list[str]]:
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout, follow_redirects=True) as client:
                resp = await client.get(f"https://{domain}")
        except httpx.RequestError:
            return None, []

        tech_signals: list[str] = []
        server_header = resp.headers.get("server", "").lower()
        if "cloudflare" in server_header:
            tech_signals.append("cloudflare")
        if "nginx" in server_header:
            tech_signals.append("nginx")
        if "apache" in server_header:
            tech_signals.append("apache")

        title_match = _TITLE_RE.search(resp.text or "")
        title = title_match.group(1).strip() if title_match else None
        return title, tech_signals

    @staticmethod
    def _extract_keywords(registrant_org: str | None, page_title: str | None) -> list[str]:
        text = " ".join(filter(None, [registrant_org, page_title]))
        return list({w.lower() for w in _WORD_RE.findall(text)})
