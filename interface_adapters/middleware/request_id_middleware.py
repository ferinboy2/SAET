import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from infrastructure.logging.request_context import new_request_id, set_request_id

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Generate request id ใหม่ทุก request, เก็บใน contextvar (ให้ logging filter หยิบไปใช้),
    แปะกลับใน response header `X-Request-ID` (ให้ client เอาไปอ้างอิงตอน report bug ได้),
    และ log summary ของทุก request (method, path, status, duration)
    """

    async def dispatch(self, request: Request, call_next):
        request_id = new_request_id()
        set_request_id(request_id)
        start = time.monotonic()

        response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "%s %s -> %d (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response
