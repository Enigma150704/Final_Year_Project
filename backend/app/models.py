from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Union
from enum import Enum
from datetime import datetime, timezone

class LifecycleStatus(str, Enum):
    CANDIDATE = "candidate"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"

class ScanStage(str, Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    PROFILING = "profiling"
    SCANNING = "scanning"
    NORMALIZING = "normalizing"
    RETRIEVING_CONTEXT = "retrieving_context"
    REASONING = "reasoning"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# --- Project & Snapshot Models ---
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=500)
    authorization_acknowledged: bool = Field(
        ...,
        description="Explicit confirmation that user is authorized to assess this repository"
    )

class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    authorization_acknowledged: bool
    created_at: str
    scan_count: Optional[int] = 0
    last_scan_completed_at: Optional[str] = None

class RepositorySnapshotResponse(BaseModel):
    id: str
    project_id: str
    source_type: str = "zip"
    original_filename: str
    content_hash: str
    storage_path: str
    commit_ref: Optional[str] = None
    created_at: str

# --- Scan & Orchestration Models ---
class ScanCreate(BaseModel):
    snapshot_id: Optional[str] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)

class ScanResponse(BaseModel):
    id: str
    project_id: str
    snapshot_id: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)
    progress: int = 0
    error_summary: Optional[str] = None

# --- Repository Profile Models ---
class RepositoryProfileResponse(BaseModel):
    id: Optional[str] = None
    scan_id: str
    languages: Dict[str, int] = Field(default_factory=dict)
    frameworks: List[str] = Field(default_factory=list)
    manifests: List[str] = Field(default_factory=list)
    dependencies_summary: List[str] = Field(default_factory=list)
    file_count: int = 0
    total_bytes: int = 0
    warnings: List[str] = Field(default_factory=list)
    created_at: Optional[str] = None

# Backward compatibility alias
class ProjectProfile(BaseModel):
    project_id: str
    project_name: str
    file_count: int
    languages: Dict[str, int]
    frameworks: List[str] = Field(default_factory=list)
    dependency_files: List[str] = Field(default_factory=list)
    entrypoint_candidates: List[str] = Field(default_factory=list)
    scanned_at: str

# --- Analyzer Models ---
class AnalyzerRunResponse(BaseModel):
    id: str
    scan_id: str
    analyzer_name: str
    analyzer_version: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    exit_code: Optional[int] = None
    error_summary: Optional[str] = None

# --- Evidence & Context Models ---
class Evidence(BaseModel):
    file: str
    start_line: int
    end_line: int
    excerpt: str
    source: str

class EvidenceDetail(BaseModel):
    id: Optional[str] = None
    finding_id: Optional[str] = None
    source_type: str
    analyzer_reference: str
    description: Optional[str] = None
    file_path: str
    line_start: int
    line_end: int
    content_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ContextBundleModel(BaseModel):
    id: Optional[str] = None
    finding_id: Optional[str] = None
    context_type: str
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    content_redacted: str
    retrieval_method: str

# --- Finding Models ---
class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: str
    title: str
    description: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    cwe: Optional[str] = None
    category: str = "General"
    file: str
    start_line: int
    end_line: int
    evidence: List[Evidence] = Field(default_factory=list)
    remediation: str
    source: str
    status: str = "needs_review"
    stable_fingerprint: Optional[str] = None

class FindingResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    scan_id: str
    stable_fingerprint: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    cwe: Optional[str] = None
    file_path: str
    start_line: int
    end_line: int
    evidence_excerpt_redacted: str
    lifecycle_status: str
    remediation: str
    created_at: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    context_bundles: List[Dict[str, Any]] = Field(default_factory=list)
    ai_assessment: Optional[Dict[str, Any]] = None

class FindingStatusUpdate(BaseModel):
    lifecycle_status: LifecycleStatus
    comment: Optional[str] = Field(None, max_length=500)
    actor: Optional[str] = Field("reviewer", max_length=100)

# --- AI Assessment Schema ---
class AIAssessmentResult(BaseModel):
    verdict: str = Field(..., description="confirmed_candidate, false_positive_candidate, or inconclusive")
    rationale: str
    root_cause: str
    attacker_controlled_input: Optional[str] = None
    source_to_sink_path: Optional[str] = None
    protections_found: List[str] = Field(default_factory=list)
    missing_protections: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    impact: str
    cwe: Optional[str] = None
    severity_suggestion: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_references: List[str] = Field(default_factory=list)
    remediation: str
    regression_test_idea: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)

# --- Scan Result & Report Models ---
class ScanResult(BaseModel):
    project_id: str
    profile: ProjectProfile
    findings: List[Finding]
    summary: Dict[str, int]
    scanner_mode: str
    warnings: List[str] = Field(default_factory=list)
    completed_at: str

class ReportResponse(BaseModel):
    title: str = "AI Vulnerability Discovery Report"
    project: Dict[str, Any]
    scan: Dict[str, Any]
    summary: Dict[str, int]
    scanner_mode: str
    tools: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    generated_at: str
    content_hash: str

class AuditEventModel(BaseModel):
    id: str
    project_id: Optional[str] = None
    scan_id: Optional[str] = None
    actor: str
    event_type: str
    details: Dict[str, Any]
    timestamp: str
