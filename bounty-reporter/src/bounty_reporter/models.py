"""The Finding model: structured, validated evidence for one vulnerability.

Required fields mirror the report-writer skill's 'required inputs': without a
vuln type, an affected asset, reproduction steps, an observed result, and an
impact statement, a report cannot be honestly written — so the model refuses to
construct one rather than inventing the missing pieces.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class Finding(BaseModel):
    program: str
    vuln_type: str
    asset: str  # exact URL / endpoint / parameter under test
    steps_to_reproduce: list[str] = Field(min_length=1)
    observed_result: str
    impact: str

    # Strongly recommended, not strictly required.
    summary: str | None = None
    title: str | None = None
    affected_param: str | None = None
    poc_request: str | None = None
    poc_response: str | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)

    @field_validator("program", "vuln_type", "asset", "observed_result", "impact")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must not be blank")
        return value.strip()

    @field_validator("steps_to_reproduce")
    @classmethod
    def _steps_non_blank(cls, steps: list[str]) -> list[str]:
        cleaned = [s.strip() for s in steps if s and s.strip()]
        if not cleaned:
            raise ValueError("at least one non-blank reproduction step is required")
        return cleaned

    @field_validator("cwe")
    @classmethod
    def _cwe_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        v = value.strip().upper()
        if not v.startswith("CWE-"):
            raise ValueError("cwe must look like 'CWE-79'")
        return v

    def resolved_title(self) -> str:
        """Use the provided title, or synthesize one in the skill's
        `<vuln> on <asset> allows <impact>` shape from real fields only."""
        if self.title:
            return self.title.strip()
        impact_clause = self.impact.strip().rstrip(".")
        if len(impact_clause) > 80:
            impact_clause = impact_clause[:77].rstrip() + "..."
        return f"{self.vuln_type} on {self.asset} allows {impact_clause}"

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Build a Finding, raising a friendly error listing missing fields."""
        from pydantic import ValidationError

        try:
            return cls(**data)
        except ValidationError as exc:
            missing = [
                ".".join(str(p) for p in err["loc"])
                for err in exc.errors()
                if err["type"] in ("missing", "value_error")
            ]
            raise ValueError(
                "Finding is missing required evidence: "
                + ", ".join(missing)
                + ". Supply these rather than fabricating them."
            ) from exc
