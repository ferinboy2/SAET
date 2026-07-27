# SA&ET Platform — Phase 0-1 Scaffold

Clean Architecture scaffold ของ Situational Awareness & Emerging Threats module
(ส่วนหนึ่งของ VANTAGE SOC) พร้อม Ports/Interfaces ครบ, Mock Gateway สำหรับ dev/test,
และ MISP adapter จริงที่พร้อมต่อเมื่อมี instance

## ติดตั้ง

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## รัน Unit Test (ใช้ Mock Gateway — ไม่ต้องมี MISP จริง)

```bash
pytest -v
```

## รัน API (default = mock provider)

```bash
uvicorn main:app --reload
```

ทดสอบ:
```bash
curl "http://localhost:8000/api/v1/ioc/search?value=1.2.3.4"
```

## Phase 3: CII Sector / Domain Matching

```bash
# ระบุ sector ตรงๆ
curl "http://localhost:8000/api/v1/org/assess?sector=finance_banking"

# หรือระบุ domain แทน (ระบบทำ passive recon แล้วเดา sector ให้)
curl "http://localhost:8000/api/v1/org/assess?domain=examplebank.co.th"
```

Default ใช้ `MockDomainReconGateway` (ข้อมูลจำลอง 2 domain: `examplebank.co.th`,
`exampleagency.go.th`) และ `KeywordSectorClassifier` (rule-based, ให้คะแนนจาก
keyword ไทย/อังกฤษ + TLD hint เช่น `.go.th` -> public_service)

สลับไปใช้ passive recon จริง (WHOIS/DNS/HTTP) ตั้งค่า:
```
DOMAIN_RECON_PROVIDER=passive
```
ต้องมี network egress ไปยัง WHOIS/DNS/เว็บไซต์เป้าหมาย และ `pip install dnspython python-whois`
(อยู่ใน requirements.txt แล้ว)

## Phase 4: MITRE ATT&CK Mapping

```bash
# ดู ATT&CK mapping ของ threat ทั้งหมดใน sector หนึ่ง พร้อมคำแนะนำ Prevent/Detect/Respond
curl "http://localhost:8000/api/v1/attack/mapping?sector=finance_banking"

# ดูรายละเอียด technique เดี่ยวๆ
curl "http://localhost:8000/api/v1/attack/technique/T1486"
```

`StaticAttackMapper` ใช้ catalog แบบ curated ใน `infrastructure/attack/attack_technique_catalog.py`
(ครอบคลุม technique ที่พบบ่อยใน SOC เช่น Phishing, Valid Accounts, Ransomware, C2 ฯลฯ)
รองรับ fallback จาก sub-technique (เช่น T1566.001) ไปหา parent (T1566) ถ้ายังไม่มีข้อมูลเฉพาะ
ขยาย catalog เพิ่มได้ตรงๆ ในไฟล์นั้น หรือสลับไปโหลดจาก MITRE ATT&CK STIX bundle เต็มรูปแบบ
ในอนาคตโดยเขียน mapper ใหม่ implement `AttackMapper` แทนได้ ไม่กระทบ use case/controller

## Phase 5: Risk Engine (Risk Score รายพนักงาน)

```bash
curl -X POST "http://localhost:8000/api/v1/risk/score" \
  -H "Content-Type: application/json" \
  -d '{
    "employee": {
      "id": "emp-001",
      "name": "Somchai",
      "department": "Finance",
      "access_level": "executive",
      "recent_phishing_click_rate": 0.7,
      "completed_trainings": []
    },
    "sector": "finance_banking"
  }'
```

`RuleBasedRiskEngine` คำนวณ 3 มิติถ่วงน้ำหนัก (Exposure 35% / Behavior 35% / Threat Landscape 30%):
- **Exposure** — จาก access level (standard/privileged/executive)
- **Behavior** — จาก phishing click rate ล่าสุด หักลดตามจำนวน training ที่ผ่านแล้ว
- **Threat Landscape** — จากจำนวน threat event ที่ active ใน sector ตอนนี้ (ผ่าน `ThreatIntelGateway`)

พร้อมแนะนำ `recommended_training_tags` จาก MITRE ATT&CK technique ที่พบในภัยคุกคาม active
(ใช้ catalog เดียวกับ Phase 4) โดยไม่แนะนำหัวข้อที่พนักงานผ่านการอบรมไปแล้ว

เปลี่ยนไปใช้โมเดล ML ในอนาคตได้โดยเขียน engine ใหม่ implement `RiskEngine` port แทน
ไม่กระทบ use case/controller

## Phase 6: Training Content Generator (ต่อ Claude API)

```bash
# รวม Risk Score (Phase 5) + Training Content (Phase 6) ในคำขอเดียว
curl -X POST "http://localhost:8000/api/v1/training/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "employee": {
      "id": "emp-001", "name": "Somchai", "department": "Finance",
      "access_level": "executive", "recent_phishing_click_rate": 0.7,
      "completed_trainings": []
    },
    "sector": "finance_banking"
  }'
```

ต่อ Claude API จริง ตั้งค่า:
```
ANTHROPIC_API_KEY=sk-ant-xxxxx
ANTHROPIC_MODEL=claude-sonnet-5   # default อยู่แล้ว เลือก Sonnet เพราะประหยัด token
```

**ไม่มี API key ก็ใช้งานได้** — `ClaudeContentGenerator` จะ fail ทันที แล้วระบบ fallback
ไป `TemplateContentGenerator` อัตโนมัติ (เนื้อหา awareness พื้นฐานคงที่ ไม่พึ่ง AI/network)
response จะ label `"generated_by": "template"` ให้เห็นชัดว่าเนื้อหามาจากไหน

Prompt engineering ทั้งหมดอยู่ใน `GenerateTrainingUseCase` (business logic) ไม่ใช่ใน
`ClaudeContentGenerator` (infra) — สลับ AI provider ในอนาคตได้โดยไม่ต้องแก้ prompt ที่ไหนเลย

## Phase 7: UI/Dashboard

```bash
# 1. รัน backend
uvicorn main:app --reload

# 2. เปิด frontend/index.html ในเบราว์เซอร์ตรงๆ (ไม่ต้อง build step ใดๆ)
```

Dashboard เป็น single-file HTML (React ผ่าน CDN + Babel standalone) สไตล์ dark
ops-console ตาม coding standard เดิมของทีม (IBM Plex Mono, dark theme) มี 4 โมดูล
ตรงกับ endpoint ที่สร้างไว้: IOC Search, CII Sector/Domain Assessment, ATT&CK
Mapping, Risk Engine & Training — ปรับ API base URL ได้จากช่องบน top bar
(default `http://localhost:8000`)

## Phase 8: Hardening

**Structured logging + Request tracing** — ทุก log line มี `request_id` เดียวกันตลอด
ทั้ง request (ผ่าน `contextvars`) ต่อ log จาก controller/use case/infra layer ให้เป็น
request เดียวกันได้ทันทีตอน debug production เปิดดูด้วย:
```bash
LOG_LEVEL=DEBUG uvicorn main:app
```
Response ทุกอันจะมี header `X-Request-ID` ให้ client อ้างอิงตอน report ปัญหา

**Rate limiting** — `RateLimitedThreatIntelGateway` (decorator pattern, wrap
`ThreatIntelGateway` ใดๆ) จำกัดจำนวนครั้งที่ยิง MISP/mock ในหน้าต่างเวลาที่กำหนด
ค่า default 30 ครั้ง/60 วินาที ปรับได้:
```
THREAT_INTEL_RATE_LIMIT_MAX_CALLS=30
THREAT_INTEL_RATE_LIMIT_WINDOW_SECONDS=60
```
โดนก็ fail-fast ทันที (`ThreatIntelRateLimitError`) ซึ่งเป็น subtype ของ
`ThreatIntelUnavailableError` — ทำให้ use case ที่มี cache fallback อยู่แล้ว
(เช่น `SearchIOCUseCase`) ทำงานถูกต้องอัตโนมัติโดยไม่ต้องแก้โค้ด

**Global exception handler** — uncaught exception ใดๆ จะไม่หลุด stack trace/ข้อความ
ภายในไปหา client (ป้องกัน information disclosure) client เห็นแค่
`{"detail": "internal server error", "request_id": "..."}` ส่วน log เต็มพร้อม
traceback อยู่ฝั่ง server เท่านั้น

**Error mapping ที่ endpoint ทุกตัว** — `interface_adapters/api/error_mapping.py`
แปล `ThreatIntelAuthError` → 502, `ThreatIntelUnavailableError` (รวม rate limit) → 503
ใช้ร่วมกันทุก controller ที่แตะ `ThreatIntelGateway` (ค้นพบระหว่างทดสอบว่า org/attack/risk
controller เดิมยังไม่ได้ดัก exception เหล่านี้ ตกไปเป็น 500 ทั่วไป — แก้แล้ว)

## สลับไปใช้ MISP จริง

ตั้งค่า environment variable (หรือไฟล์ `.env`):

```
THREAT_INTEL_PROVIDER=misp
MISP_BASE_URL=https://your-misp-instance
MISP_API_KEY=xxxxxxxx
```

ไม่ต้องแก้โค้ด use case หรือ controller ใดๆ เลย — `Container.threat_intel_gateway()`
เป็นจุดเดียวที่ตัดสินใจว่าจะใช้ implementation ไหน

## สถานะแต่ละ Phase

| Phase | สถานะ |
|---|---|
| 0 — Setup/DI/config | ✅ เสร็จ |
| 1 — Domain + Ports + IOC Search use case | ✅ เสร็จ (พร้อม test) |
| 2 — MISP adapter จริง | ✅ โครงพร้อม รอต่อ instance จริงเพื่อทดสอบ end-to-end |
| 3 — CII Sector / Domain matching | ✅ เสร็จ (mock recon + keyword classifier, พร้อม test) — passive recon จริงพร้อมใช้เมื่อมี network |
| 4 — MITRE ATT&CK mapping | ✅ เสร็จ (curated catalog + parent fallback, พร้อม test) |
| 5 — Risk Engine | ✅ เสร็จ (rule-based, 3 มิติถ่วงน้ำหนัก, พร้อม test) |
| 6 — Training generator | ✅ เสร็จ (ต่อ Claude API จริง + template fallback, พร้อม test) |
| 7 — UI/Dashboard | ✅ เสร็จ (single-file dark ops-console dashboard, ทดสอบผ่าน jsdom) |
| 8 — Hardening | ✅ เสร็จ (structured logging, request tracing, rate limit, global exception handler, error mapping ครบทุก controller) |
| 8 — Hardening | ยังไม่เริ่ม |

## โครงสร้าง

ดู `SAET_Project_Plan.md` สำหรับสถาปัตยกรรมเต็มรูปแบบ
