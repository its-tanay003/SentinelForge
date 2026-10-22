"""Configuration management for SentinelForge."""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    APP_NAME: str = "SentinelForge"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/sentinelforge.db"

    # API Keys (optional - will fall back to mock data)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

    # Webhook (optional)
    SOAR_WEBHOOK_URL: str = os.getenv("SOAR_WEBHOOK_URL", "")

    # Reports output directory
    REPORTS_DIR: Path = BASE_DIR / "reports"

    # Demo target
    DEMO_TARGET_URL: str = os.getenv("DEMO_TARGET_URL", "http://localhost:9000")

    # Scanner timeouts
    HTTP_TIMEOUT: float = float(os.getenv("HTTP_TIMEOUT", "10.0"))

    # Intel cache TTL (seconds)
    INTEL_CACHE_TTL: int = int(os.getenv("INTEL_CACHE_TTL", "3600"))


settings = Settings()
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
