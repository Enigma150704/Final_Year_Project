from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, BackgroundTasks, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import uuid
import shutil
import json
import os

from .database import DatabaseManager, DB_PATH
from .security import safe_extract_zip_with_metadata
from .models import (
    ProjectCreate, ProjectResponse, RepositorySnapshotResponse,
    ScanCreate, ScanResponse, RepositoryProfileResponse,
    FindingResponse, FindingStatusUpdate, ReportResponse,
    AnalyzerRunResponse
)
from .orchestrator import execute_scan_pipeline

APP_ROOT = Path(os.environ.get("VULN_MVP_ROOT", Path(__file__).resolve().parents[2]))
DATA_DIR = Path(os.environ.get("VULN_MVP_DATA", APP_ROOT / "data"))
PROJECTS_DIR = DATA_DIR / "projects"
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)

db = DatabaseManager(DB_PATH)

app = FastAPI(
    title="AI-Driven Vulnerability Discovery System API",
    version="1.0.0",
    description="Defensive repository analysis, normalized findings, evidence construction, and reviewer controls."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- Frontend Home ---
@app.get("/", response_class=HTMLResponse)
def home():
    html_file = APP_ROOT / "frontend" / "index.html"
    if html_file.exists():
        return html_file.read_text(encoding="utf-8")
    return "<h1>AI-Driven Vulnerability Discovery System</h1><p>Frontend file not found.</p>"

# --- Health Check ---
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ai-vulnerability-discovery-mvp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# --- Project Endpoints ---
@app.post("/api/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate):
    if not payload.authorization_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Authorization acknowledgement is required. You may only analyze repositories you own or are explicitly authorized to test."
        )
    project = db.create_project(
        name=payload.name,
        description=payload.description,
        authorization_acknowledged=payload.authorization_acknowledged
    )
    return project

@app.get("/api/projects", response_model=List[ProjectResponse])
def list_projects():
    return db.list_projects()

@app.get("/api/projects/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str):
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")
    return project

# --- Repository Intake ---
@app.post("/api/projects/{project_id}/repositories", response_model=RepositorySnapshotResponse)
async def upload_repository(
    project_id: str,
    file: UploadFile = File(...),
    authorization_acknowledged: bool = Form(True)
):
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")

    if not authorization_acknowledged and not project["authorization_acknowledged"]:
        raise HTTPException(
            status_code=400,
            detail="Authorization must be acknowledged before uploading repository archives."
        )

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP archives are supported.")

    data = await file.read()
    snapshot_id = uuid.uuid4().hex[:12]
    repo_extract_dir = PROJECTS_DIR / project_id / snapshot_id / "source"

    try:
        file_count, total_bytes, content_hash = safe_extract_zip_with_metadata(data, repo_extract_dir)
    except ValueError as exc:
        shutil.rmtree(PROJECTS_DIR / project_id / snapshot_id, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc))

    snapshot = db.create_snapshot(
        project_id=project_id,
        original_filename=file.filename,
        content_hash=content_hash,
        storage_path=str(repo_extract_dir),
        snapshot_id=snapshot_id
    )
    return snapshot

# --- Scan Orchestration ---
@app.post("/api/projects/{project_id}/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    project_id: str,
    payload: Optional[ScanCreate] = None,
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")

    snapshot_id = payload.snapshot_id if payload and payload.snapshot_id else None
    if not snapshot_id:
        latest = db.get_latest_snapshot_for_project(project_id)
        if not latest:
            raise HTTPException(status_code=400, detail="No repository snapshot found for this project. Upload a ZIP archive first.")
        snapshot_id = latest["id"]
    else:
        snapshot = db.get_snapshot(snapshot_id)
        if not snapshot or snapshot["project_id"] != project_id:
            raise HTTPException(status_code=404, detail="Specified snapshot not found for this project.")

    config = payload.configuration if payload else {}
    scan = db.create_scan(project_id=project_id, snapshot_id=snapshot_id, configuration=config)
    
    # Run pipeline in background task
    background_tasks.add_task(execute_scan_pipeline, scan["id"], db)
    return scan

@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan

@app.get("/api/scans/{scan_id}/profile", response_model=RepositoryProfileResponse)
def get_scan_profile(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    profile = db.get_profile(scan_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Repository profile not yet generated for this scan.")
    return profile

@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingResponse])
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    status: Optional[str] = Query(None, description="Filter by lifecycle status (candidate, needs_review, confirmed, rejected)"),
    cwe: Optional[str] = Query(None, description="Filter by CWE (e.g. CWE-89)"),
    file_path: Optional[str] = Query(None, description="Filter by matching file path")
):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    findings = db.list_findings(scan_id, severity=severity, status=status, cwe=cwe, file_path=file_path)
    return findings

@app.get("/api/scans/{scan_id}/tools", response_model=List[AnalyzerRunResponse])
def get_scan_tools(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return db.list_analyzer_runs(scan_id)

@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan["status"] in ("completed", "failed", "cancelled"):
        return {"message": f"Scan is already {scan['status']}."}
    db.update_scan_status(scan_id, "cancelled", error_summary="Cancelled by user request.", completed=True)
    return {"message": "Scan cancelled."}

# --- Finding Details & Reviewer Status ---
@app.get("/api/findings/{finding_id}", response_model=FindingResponse)
def get_finding_detail(finding_id: str):
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding

@app.patch("/api/findings/{finding_id}", response_model=FindingResponse)
def update_finding_lifecycle_status(finding_id: str, payload: FindingStatusUpdate):
    updated = db.update_finding_status(
        finding_id=finding_id,
        status=payload.lifecycle_status.value,
        actor=payload.actor or "reviewer",
        comment=payload.comment
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return updated

# --- Report Generation ---
@app.get("/api/scans/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    report_data = db.get_report(scan_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="Report not ready yet.")
    return report_data["payload"]

# --- Legacy Backwards Compatibility Endpoints ---
@app.post("/api/analyze")
async def analyze_legacy(
    project_name: str = Form("Uploaded repository"),
    file: UploadFile = File(...),
    authorization_acknowledged: bool = Form(True)
):
    """
    Backwards-compatible synchronous analysis endpoint that creates project,
    snapshot, runs the pipeline, and returns the full scan report.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a ZIP archive of the authorized source repository.")

    project = db.create_project(name=project_name[:120], authorization_acknowledged=authorization_acknowledged)
    project_id = project["id"]

    data = await file.read()
    snapshot_id = uuid.uuid4().hex[:12]
    repo_extract_dir = PROJECTS_DIR / project_id / snapshot_id / "source"

    try:
        file_count, total_bytes, content_hash = safe_extract_zip_with_metadata(data, repo_extract_dir)
    except ValueError as exc:
        shutil.rmtree(PROJECTS_DIR / project_id / snapshot_id, ignore_errors=True)
        raise HTTPException(400, str(exc))

    snapshot = db.create_snapshot(
        project_id=project_id,
        original_filename=file.filename,
        content_hash=content_hash,
        storage_path=str(repo_extract_dir),
        snapshot_id=snapshot_id
    )

    scan = db.create_scan(project_id=project_id, snapshot_id=snapshot["id"])
    report_data = execute_scan_pipeline(scan["id"], db)

    # Transform for legacy frontend format
    legacy_findings = []
    for f in report_data["findings"]:
        legacy_findings.append({
            "finding_id": f["id"],
            "title": f["title"],
            "description": f["description"],
            "severity": f["severity"],
            "confidence": f["confidence"],
            "cwe": f["cwe"],
            "category": f.get("category", "General"),
            "file": f["file_path"],
            "start_line": f["start_line"],
            "end_line": f["end_line"],
            "evidence": [
                {
                    "file": ev["file_path"],
                    "start_line": ev["line_start"],
                    "end_line": ev["line_end"],
                    "excerpt": f["evidence_excerpt_redacted"],
                    "source": ev["source_type"]
                } for ev in f.get("evidence", [])
            ],
            "retrieved_context": [
                {
                    "file": cb["file_path"],
                    "relevance": f"{cb['context_type']} ({cb['retrieval_method']})",
                    "content": cb["content_redacted"]
                } for cb in f.get("context_bundles", [])
            ],
            "remediation": f["remediation"],
            "source": f["rule_id"],
            "status": f["lifecycle_status"]
        })

    return {
        "project_id": project_id,
        "scan_id": scan["id"],
        "profile": report_data["profile"],
        "findings": legacy_findings,
        "summary": report_data["summary"],
        "scanner_mode": report_data["scanner_mode"],
        "warnings": report_data["warnings"],
        "completed_at": report_data["generated_at"]
    }

@app.get("/api/projects/{project_id}/findings/{finding_id}")
def get_project_finding_legacy(project_id: str, finding_id: str):
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    return finding

@app.get("/api/projects/{project_id}/report")
def get_project_report_legacy(project_id: str):
    scans = db.list_scans_for_project(project_id)
    if not scans:
        raise HTTPException(404, "No scans found for this project.")
    latest_scan_id = scans[0]["id"]
    report = db.get_report(latest_scan_id)
    if not report:
        raise HTTPException(404, "Report not found.")
    return report["payload"]
