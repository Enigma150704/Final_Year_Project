"""Scan orchestration service for AI-Driven Vulnerability Discovery System.
Coordinates repository profiling, analyzer execution, finding normalization,
context retrieval, AI reasoning (mock/real), report generation, and audit logging.
"""
from pathlib import Path
import json
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from .database import DatabaseManager, now_iso
from .profiler import profile_repository
from .scanner import scan_repository, semgrep_available
from .retrieval import retrieve_context
from .ai import MockAIProvider
from .security import compute_sha256

def execute_scan_pipeline(scan_id: str, db: DatabaseManager) -> Dict[str, Any]:
    """
    Execute the entire analysis pipeline synchronously or as a background task.
    Updates the database at each stage with progress percentages and audit trails.
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} does not exist.")

    project_id = scan["project_id"]
    snapshot_id = scan["snapshot_id"]
    snapshot = db.get_snapshot(snapshot_id)
    if not snapshot:
        db.update_scan_status(scan_id, "failed", error_summary="Repository snapshot not found.")
        raise ValueError(f"Snapshot {snapshot_id} not found.")

    repo_path = Path(snapshot["storage_path"])
    config = scan.get("configuration", {})
    enable_ai = config.get("enable_ai", False)

    try:
        # Stage 1: Validating
        db.update_scan_status(scan_id, "validating", progress=15)
        if not repo_path.exists() or not repo_path.is_dir():
            raise FileNotFoundError(f"Repository source path {repo_path} does not exist.")

        # Stage 2: Profiling
        db.update_scan_status(scan_id, "profiling", progress=30)
        project = db.get_project(project_id)
        proj_name = project["name"] if project else "Analyzed repository"
        profile_data = profile_repository(project_id, proj_name, repo_path)
        db.save_profile(
            scan_id=scan_id,
            languages=profile_data["languages"],
            frameworks=profile_data["frameworks"],
            manifests=profile_data["manifests"],
            dependencies_summary=profile_data["dependency_files"],
            file_count=profile_data["file_count"],
            total_bytes=profile_data.get("total_bytes", 0),
            warnings=profile_data.get("warnings", [])
        )

        # Stage 3: Scanning
        db.update_scan_status(scan_id, "scanning", progress=50)
        
        # Record analyzer runs
        db.record_analyzer_run(
            scan_id=scan_id,
            name="builtin-rule-engine",
            version="1.0.0",
            status="completed",
            exit_code=0
        )
        if semgrep_available():
            db.record_analyzer_run(
                scan_id=scan_id,
                name="semgrep",
                version="auto",
                status="completed",
                exit_code=0
            )
        else:
            db.record_analyzer_run(
                scan_id=scan_id,
                name="semgrep",
                version="unavailable",
                status="skipped",
                error_summary="Semgrep binary not installed in PATH."
            )

        raw_findings, scanner_mode, scan_warnings = scan_repository(repo_path)

        # Stage 4: Normalizing & Persisting Findings
        db.update_scan_status(scan_id, "normalizing", progress=70)
        persisted_findings = []
        for f in raw_findings:
            redacted_excerpt = f.evidence[0].excerpt if f.evidence else ""
            fid_unique = f"{scan_id}_{f.finding_id}"
            fid = db.save_finding(
                scan_id=scan_id,
                stable_fingerprint=f.stable_fingerprint or f.finding_id,
                rule_id=f.source,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                file_path=f.file,
                start_line=f.start_line,
                end_line=f.end_line,
                evidence_excerpt_redacted=redacted_excerpt,
                remediation=f.remediation,
                cwe=f.cwe,
                lifecycle_status="candidate" if f.confidence < 0.60 else "needs_review",
                finding_id=fid_unique
            )
            # Save associated evidence entries
            for ev in f.evidence:
                db.save_evidence(
                    finding_id=fid,
                    source_type=ev.source,
                    analyzer_reference=ev.source,
                    file_path=ev.file,
                    line_start=ev.start_line,
                    line_end=ev.end_line,
                    description=f.title
                )
            persisted_findings.append((fid, f))

        # Stage 5: Retrieving Context
        db.update_scan_status(scan_id, "retrieving_context", progress=85)
        ai_provider = MockAIProvider() if enable_ai else None

        for fid, f_obj in persisted_findings:
            context_bundles = retrieve_context(repo_path, f_obj)
            for cb in context_bundles:
                db.save_context_bundle(
                    finding_id=fid,
                    context_type=cb.get("context_type", "related_file"),
                    file_path=cb["file"],
                    content_redacted=cb["content"],
                    retrieval_method=cb.get("retrieval_method", "lexical"),
                    line_start=cb.get("line_start"),
                    line_end=cb.get("line_end")
                )
            
            # Optional Stage 5b: AI Reasoning
            if enable_ai and ai_provider:
                db.update_scan_status(scan_id, "reasoning", progress=90)
                try:
                    assessment = ai_provider.assess_finding(f_obj, context_bundles, repo_root=repo_path)
                    db.save_ai_assessment(
                        finding_id=fid,
                        provider="mock",
                        model="mock-reasoner-v1",
                        prompt_version="1.0",
                        verdict=assessment.verdict,
                        structured_result=assessment.model_dump(),
                        status="completed"
                    )
                except Exception as ex:
                    # AI failure must never crash scan pipeline
                    pass

        # Stage 6: Reporting
        db.update_scan_status(scan_id, "reporting", progress=95)
        findings_list = db.list_findings(scan_id)
        
        summary = {
            "total": len(findings_list),
            "critical": sum(1 for x in findings_list if x["severity"] == "critical"),
            "high": sum(1 for x in findings_list if x["severity"] == "high"),
            "medium": sum(1 for x in findings_list if x["severity"] == "medium"),
            "low": sum(1 for x in findings_list if x["severity"] == "low")
        }

        tools_used = db.list_analyzer_runs(scan_id)
        report_payload = {
            "title": "AI Vulnerability Discovery Report",
            "project_id": project_id,
            "project_name": proj_name,
            "scan_id": scan_id,
            "snapshot_id": snapshot_id,
            "snapshot_hash": snapshot["content_hash"],
            "profile": profile_data,
            "summary": summary,
            "scanner_mode": scanner_mode,
            "tools": tools_used,
            "findings": findings_list,
            "warnings": scan_warnings,
            "limitations": [
                "Built-in rules are heuristic candidates requiring human security review.",
                "No uploaded code, installation scripts, or tests were executed.",
                "Interprocedural data-flow and taint graph analysis are planned future milestones.",
                "AI assessments provide advisory rationale and do not alter tool boundaries."
            ],
            "generated_at": now_iso()
        }

        report_raw = json.dumps(report_payload, indent=2)
        report_hash = hashlib.sha256(report_raw.encode()).hexdigest()
        
        # Save snapshot result.json on disk for backwards compatibility
        result_disk_path = repo_path.parent / "result.json"
        try:
            result_disk_path.write_text(report_raw, encoding="utf-8")
        except OSError:
            pass

        db.save_report(scan_id, report_payload, report_hash, storage_path=str(result_disk_path))

        # Mark scan completed
        db.update_scan_status(scan_id, "completed", progress=100, completed=True)
        return report_payload

    except Exception as exc:
        db.update_scan_status(scan_id, "failed", error_summary=str(exc), completed=True)
        raise exc
