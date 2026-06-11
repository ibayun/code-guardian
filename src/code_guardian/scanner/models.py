from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from code_guardian.config import Severity


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vuln_id: str = Field(alias="VulnerabilityID")
    pkg_name: str = Field(alias="PkgName")
    severity: Severity = Field(Severity.UNKNOWN, alias="Severity")
    title: str = Field("", alias="Title")
    description: str = Field("", alias="Description")
    fixed_version: str | None = Field(None, alias="FixedVersion")
    installed_version: str = Field("", alias="InstalledVersion")

    def __str__(self) -> str:
        return f"{self.vuln_id} [{self.severity.value}] {self.pkg_name}"


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    target: str = Field(alias="Target")
    class_: str = Field("", alias="Class")
    type: str = ""
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list, alias="Vulnerabilities"
    )


class Dependency(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(alias="ID")
    depends_on: list[str] = Field(default_factory=list, alias="DependsOn")


class TrivyReport(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schema_version: int = Field(2, alias="SchemaVersion")
    artifact_name: str = Field("", alias="ArtifactName")
    results: list[ScanResult] = Field(default_factory=list, alias="Results")
    dependencies: list[Dependency] = Field(default_factory=list, alias="Dependencies")
