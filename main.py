import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import Settings
from infrastructure.logging.logging_config import setup_logging
from infrastructure.logging.request_context import get_request_id
from interface_adapters.api.attack_controller import router as attack_router
from interface_adapters.api.ioc_controller import router as ioc_router
from interface_adapters.api.org_controller import router as org_router
from interface_adapters.api.risk_controller import router as risk_router
from interface_adapters.api.training_controller import router as training_router
from interface_adapters.middleware.request_id_middleware import RequestIDMiddleware

_settings = Settings()
setup_logging(level=_settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SA&ET Platform API",
    description="Situational Awareness & Emerging Threats — VANTAGE SOC module",
    version="0.1.0",
)

# เปิด CORS แบบกว้างสำหรับ dev เท่านั้น — จำกัด origin ให้แคบลงก่อน deploy จริง
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIDMiddleware)

app.include_router(ioc_router)
app.include_router(org_router)
app.include_router(attack_router)
app.include_router(risk_router)
app.include_router(training_router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    กันไม่ให้ stack trace/ error message ภายในหลุดออกไปหา client (information disclosure)
    Log รายละเอียดเต็มฝั่ง server พร้อม request_id ให้ตามรอยได้ ส่วน response
    ที่ client เห็นมีแค่ request_id ให้ไปอ้างอิงตอน report ปัญหา
    """
    request_id = get_request_id()
    logger.exception("Unhandled exception on %s %s (req=%s)", request.method, request.url.path, request_id)
    return JSONResponse(
        status_code=500,
        content={"detail": "internal server error", "request_id": request_id},
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
