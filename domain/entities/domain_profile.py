from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DomainProfile:
    """
    ผลลัพธ์จาก passive recon ของ domain name — ไม่มีการ active scan ใดๆ
    (WHOIS, DNS records, HTTP header/meta ของหน้าแรกเท่านั้น)
    """

    domain: str
    tld: str | None = None                       # เช่น "go.th", "co.th", "com"
    registrant_org: str | None = None             # จาก WHOIS (ถ้า provider ไม่ redact)
    mx_providers: list[str] = field(default_factory=list)
    tech_signals: list[str] = field(default_factory=list)   # เช่น "wordpress", "cloudflare"
    page_title: str | None = None
    keywords: list[str] = field(default_factory=list)        # คำที่ดึงจาก org name + page title
