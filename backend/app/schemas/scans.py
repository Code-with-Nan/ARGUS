from pydantic import BaseModel, ConfigDict, Field, field_validator


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