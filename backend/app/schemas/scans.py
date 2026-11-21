from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: str
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    test_id: str
    code: str
    scanner: str = "legacy"
    rule_id: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None
    explanation: str | None = None
    explanation_source: str | None = None


class ScanSummaryResponse(BaseModel):
    scan_id: str
    project_name: str
    status: str
    scanner: str
    total_findings: int
    created_at: datetime
    updated_at: datetime | None = None
    scanner_results: dict[str, Any] = Field(default_factory=dict)


class ScanDetailResponse(ScanSummaryResponse):
    findings: list[FindingResponse] = Field(default_factory=list)
    remediations: list[dict[str, Any]] = Field(default_factory=list)


class ScanHistoryResponse(BaseModel):
    items: list[ScanSummaryResponse]
    page: int
    page_size: int
    total: int


class FindingsPageResponse(BaseModel):
    items: list[FindingResponse]
    page: int
    page_size: int
    total: int


class ScannerInfoResponse(BaseModel):
    name: str
    available: bool
    supported_file_types: list[str]


class ScannerCatalogResponse(BaseModel):
    items: list[ScannerInfoResponse]


class HealthResponse(BaseModel):
    status: str
    database: str


class ReportMetricsResponse(BaseModel):
    fix_verification_rate: float | None
    verified_resolutions: int
    completed_verifications: int
    regression_count: int
    average_remediation_seconds: float | None
    remediation_time_samples: int
    accuracy_status: str


class SecurityReportResponse(BaseModel):
    project_name: str
    scan_id: str
    scan_timestamp: datetime
    scan_status: str
    scanner_execution: dict[str, Any]
    total_findings: int
    severity_breakdown: dict[str, int]
    findings: list[FindingResponse]
    remediation_status: dict[str, int]
    verification_results: list[dict[str, Any]]
    metrics: ReportMetricsResponse
    limitations: list[str]


class RemediationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suggested_fix: str | None = Field(default=None, max_length=8000)
    rationale: str | None = Field(default=None, max_length=8000)
    patch: str | None = Field(default=None, max_length=100000)


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved_by: str = Field(min_length=1, max_length=255)

    @field_validator("approved_by")
    @classmethod
    def require_nonblank_approver(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("approved_by must not be blank")
        return value.strip()