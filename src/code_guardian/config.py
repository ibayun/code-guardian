from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Severity(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __ge__(self, other: "Severity") -> bool:
        order = list(Severity)
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "Severity") -> bool:
        order = list(Severity)
        return order.index(self) > order.index(other)


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CODEGUARDIAN_")

    output_dir: Path = Field(default=Path("./results"))
    format: Literal["json", "html"] = "json"
    concurrency: int = Field(default=4, ge=1, le=32)
    timeout: int = Field(default=300, ge=10)
    severity: Severity = Severity.LOW
    fail_on: Severity | None = None
    github_token: str | None = None
    trivy_backend: Literal["auto", "native", "docker"] = "auto"
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"
