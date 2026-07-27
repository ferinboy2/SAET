from datetime import datetime

import httpx

from application.ports.threat_intel_gateway import ThreatIntelGateway
from domain.entities.ioc import IOC
from domain.entities.threat import ThreatEvent
from domain.exceptions import ThreatIntelAuthError, ThreatIntelUnavailableError


class MISPGatewayImpl(ThreatIntelGateway):
    """
    Adapter เฉพาะของ MISP — ความรู้เรื่อง MISP REST API ทั้งหมดอยู่ในไฟล์นี้ไฟล์เดียว
    ถ้าจะเปลี่ยนไปใช้ provider อื่น (OTX, ThreatFox, custom feed) เขียนคลาสใหม่
    implement ThreatIntelGateway แล้วสลับใน DI container แทนที่นี่ได้เลย
    ไม่ต้องแตะ use case หรือ domain แม้แต่บรรทัดเดียว
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": api_key, "Accept": "application/json"}
        self._timeout = timeout

    async def search_ioc(self, value: str, ioc_type: str | None = None) -> list[IOC]:
        payload: dict = {"value": value}
        if ioc_type:
            payload["type"] = ioc_type

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/attributes/restSearch",
                    headers=self._headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ThreatIntelUnavailableError("MISP request timed out") from exc
        except httpx.RequestError as exc:
            raise ThreatIntelUnavailableError(f"MISP connection failed: {exc}") from exc

        if resp.status_code == 401:
            raise ThreatIntelAuthError("MISP API key invalid or expired")
        if resp.status_code >= 500:
            raise ThreatIntelUnavailableError(f"MISP server error: {resp.status_code}")
        resp.raise_for_status()

        raw_attrs = resp.json().get("response", {}).get("Attribute", [])
        return [self._to_ioc(a) for a in raw_attrs]

    async def get_events_since(
        self, since: datetime, tags: list[str] | None = None
    ) -> list[ThreatEvent]:
        payload: dict = {"timestamp": int(since.timestamp())}
        if tags:
            payload["tags"] = tags

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/events/restSearch",
                    headers=self._headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ThreatIntelUnavailableError("MISP request timed out") from exc
        except httpx.RequestError as exc:
            raise ThreatIntelUnavailableError(f"MISP connection failed: {exc}") from exc

        if resp.status_code == 401:
            raise ThreatIntelAuthError("MISP API key invalid or expired")
        if resp.status_code >= 500:
            raise ThreatIntelUnavailableError(f"MISP server error: {resp.status_code}")
        resp.raise_for_status()

        raw_events = resp.json().get("response", [])
        return [self._to_threat_event(e.get("Event", e)) for e in raw_events]

    async def get_events_by_sector(self, sector_tag: str) -> list[ThreatEvent]:
        return await self.get_events_since(
            since=datetime.min, tags=[f"sector:{sector_tag}"]
        )

    @staticmethod
    def _to_ioc(raw: dict) -> IOC:
        return IOC(
            value=raw["value"],
            type=raw["type"],
            source="MISP",
            first_seen=raw.get("first_seen"),
            tags=[t["Tag"]["name"] for t in raw.get("Tag", [])] if raw.get("Tag") else [],
        )

    @staticmethod
    def _to_threat_event(raw: dict) -> ThreatEvent:
        return ThreatEvent(
            id=str(raw["id"]),
            title=raw.get("info", ""),
            source="MISP",
            published=datetime.fromtimestamp(int(raw.get("publish_timestamp", 0))),
            tags=[t["name"] for t in raw.get("Tag", [])] if raw.get("Tag") else [],
            iocs=[
                MISPGatewayImpl._to_ioc(a)
                for a in raw.get("Attribute", [])
            ],
            ttp_ids=[
                g["value"] for g in raw.get("Galaxy", []) if g.get("value", "").startswith("T")
            ],
        )
