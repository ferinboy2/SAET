import logging
import sys

from infrastructure.logging.request_context import get_request_id


class RequestIdFilter(logging.Filter):
    """แทรก request_id (จาก contextvar) เข้าไปใน log record ทุกอัน เพื่อ trace ข้าม layer ได้"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | req=%(request_id)s | %(name)s | %(message)s"


def setup_logging(level: str = "INFO") -> None:
    """
    เรียกครั้งเดียวตอน app startup — ตั้งค่า root logger ให้มี format ที่สม่ำเสมอ
    ทั้งระบบ พร้อม request_id ทุกบรรทัด log ทำให้ trace request เดียวข้าม
    domain/application/infrastructure layer ได้ง่ายเวลา debug production
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    handler.addFilter(RequestIdFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # uvicorn เขียน logger ของตัวเองแยก — ให้ใช้ handler เดียวกันเพื่อ format สม่ำเสมอ
    for noisy_logger in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy_logger).handlers = [handler]
        logging.getLogger(noisy_logger).propagate = False
