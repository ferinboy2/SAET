from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """โหลดค่าจาก environment variable / .env"""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Threat intel provider selection: "misp" หรือ "mock" (dev/test)
    threat_intel_provider: str = "mock"

    misp_base_url: str = ""
    misp_api_key: str = ""
    misp_timeout_seconds: float = 10.0

    # Domain recon provider selection: "mock" (dev/test) หรือ "passive" (WHOIS/DNS/HTTP จริง)
    domain_recon_provider: str = "mock"

    # Claude API สำหรับ Phase 6 (Training Content Generator)
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5"

    # Rate limit ป้องกันการยิง threat intel provider (MISP) ถี่เกินไป (Phase 8)
    threat_intel_rate_limit_max_calls: int = 30
    threat_intel_rate_limit_window_seconds: float = 60.0

    app_env: str = "development"
    log_level: str = "INFO"
