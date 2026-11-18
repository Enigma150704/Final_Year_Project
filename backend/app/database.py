"""Database module for AI-Driven Vulnerability Discovery System.
Implements SQLite persistence with thread-safe connection pooling, schema initialization,
and repository helpers for Projects, Snapshots, Scans, Profiles, Findings, Evidence,
ContextBundles, AI Assessments, Reports, and AuditEvents.
"""
from pathlib import Path
import sqlite3
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

APP_ROOT = Path(os.environ.get("VULN_MVP_ROOT", Path(__file__).resolve().parents[2]))
DATA_DIR = Path(os.environ.get("VULN_MVP_DATA", APP_ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vuln_discovery.db"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize database tables, indexes and constraints."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            authorization_acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS repository_snapshots (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'zip',
            original_filename TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            commit_ref TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            snapshot_id TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            configuration TEXT NOT NULL DEFAULT '{}',
            progress INTEGER NOT NULL DEFAULT 0,
            error_summary TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY(snapshot_id) REFERENCES repository_snapshots(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS repository_profiles (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL UNIQUE,
            languages TEXT NOT NULL DEFAULT '{}',
            frameworks TEXT NOT NULL DEFAULT '[]',
            manifests TEXT NOT NULL DEFAULT '[]',
            dependencies_summary TEXT NOT NULL DEFAULT '[]',
            file_count INTEGER NOT NULL DEFAULT 0,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            warnings TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS analyzer_runs (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            analyzer_name TEXT NOT NULL,
            analyzer_version TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            exit_code INTEGER,
            raw_output_reference TEXT,
            error_summary TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            stable_fingerprint TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            cwe TEXT,
            file_path TEXT NOT NULL,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            evidence_excerpt_redacted TEXT NOT NULL,
            lifecycle_status TEXT NOT NULL DEFAULT 'needs_review',
            remediation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            analyzer_reference TEXT NOT NULL,
            description TEXT,
            file_path TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            content_hash TEXT,
            metadata TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS context_bundles (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            context_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_start INTEGER,
            line_end INTEGER,
            content_redacted TEXT NOT NULL,
            retrieval_method TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ai_assessments (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL UNIQUE,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            prompt_version TEXT NOT NULL,
            verdict TEXT NOT NULL,
            structured_result TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL UNIQUE,
            format TEXT NOT NULL DEFAULT 'json',
            storage_path TEXT,
            payload TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            project_id TEXT,
            scan_id TEXT,
            actor TEXT NOT NULL DEFAULT 'system',
            event_type TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL
        );

        -- Indexes for query efficiency
        CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at);
        CREATE INDEX IF NOT EXISTS idx_snapshots_project ON repository_snapshots(project_id);
        CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(lifecycle_status);
        CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(stable_fingerprint);
        CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
        CREATE INDEX IF NOT EXISTS idx_context_finding ON context_bundles(finding_id);
        CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_events(project_id);
        CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_events(scan_id);
        """)
    conn.close()

class DatabaseManager:
    """Convenience data access helper for the system."""
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        init_db(self.db_path)

    def get_conn(self) -> sqlite3.Connection:
        return get_connection(self.db_path)

    # Project Operations
    def create_project(self, name: str, description: Optional[str] = None,
                       authorization_acknowledged: bool = True,
                       project_id: Optional[str] = None) -> Dict[str, Any]:
        pid = project_id or uuid.uuid4().hex[:12]
        created = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT INTO projects (id, name, description, authorization_acknowledged, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (pid, name, description or "", 1 if authorization_acknowledged else 0, created)
            )
            self.log_audit(conn, project_id=pid, event_type="PROJECT_CREATED",
                           details={"name": name, "auth_acknowledged": authorization_acknowledged})
        conn.close()
        return self.get_project(pid)

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "authorization_acknowledged": bool(row["authorization_acknowledged"]),
            "created_at": row["created_at"]
        }

    def list_projects(self) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        rows = conn.execute(
            """
            SELECT p.*,
                   COUNT(DISTINCT s.id) as scan_count,
                   MAX(s.completed_at) as last_scan_completed_at
            FROM projects p
            LEFT JOIN scans s ON p.id = s.project_id
            GROUP BY p.id
            ORDER BY p.created_at DESC
            """
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "name": r["name"],
                "description": r["description"],
                "authorization_acknowledged": bool(r["authorization_acknowledged"]),
                "created_at": r["created_at"],
                "scan_count": r["scan_count"],
                "last_scan_completed_at": r["last_scan_completed_at"]
            })
        return result

    # Repository Snapshot Operations
    def create_snapshot(self, project_id: str, original_filename: str,
                        content_hash: str, storage_path: str,
                        commit_ref: Optional[str] = None,
                        snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        sid = snapshot_id or uuid.uuid4().hex[:12]
        created = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT INTO repository_snapshots (id, project_id, source_type, original_filename, "
                "content_hash, storage_path, commit_ref, created_at) "
                "VALUES (?, ?, 'zip', ?, ?, ?, ?, ?)",
                (sid, project_id, original_filename, content_hash, storage_path, commit_ref, created)
            )
            self.log_audit(conn, project_id=project_id, event_type="SNAPSHOT_CREATED",
                           details={"snapshot_id": sid, "filename": original_filename, "hash": content_hash})
        conn.close()
        return self.get_snapshot(sid)

    def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT * FROM repository_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return dict(row)

    def get_latest_snapshot_for_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute(
            "SELECT * FROM repository_snapshots WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
            (project_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    # Scan Operations
    def create_scan(self, project_id: str, snapshot_id: str,
                    configuration: Optional[Dict[str, Any]] = None,
                    scan_id: Optional[str] = None) -> Dict[str, Any]:
        scid = scan_id or uuid.uuid4().hex[:12]
        started = now_iso()
        config_json = json.dumps(configuration or {})
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT INTO scans (id, project_id, snapshot_id, status, started_at, configuration, progress) "
                "VALUES (?, ?, ?, 'queued', ?, ?, 0)",
                (scid, project_id, snapshot_id, started, config_json)
            )
            self.log_audit(conn, project_id=project_id, scan_id=scid,
                           event_type="SCAN_QUEUED", details={"config": configuration})
        conn.close()
        return self.get_scan(scid)

    def update_scan_status(self, scan_id: str, status: str, progress: Optional[int] = None,
                           error_summary: Optional[str] = None, completed: bool = False) -> None:
        conn = self.get_conn()
        updates = ["status = ?"]
        params = [status]
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)
        if error_summary is not None:
            updates.append("error_summary = ?")
            params.append(error_summary)
        if completed:
            updates.append("completed_at = ?")
            params.append(now_iso())
        params.append(scan_id)
        query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"
        with conn:
            conn.execute(query, tuple(params))
            row = conn.execute("SELECT project_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
            pid = row["project_id"] if row else None
            self.log_audit(conn, project_id=pid, scan_id=scan_id,
                           event_type="SCAN_STATUS_UPDATED",
                           details={"status": status, "progress": progress, "error": error_summary})
        conn.close()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        if not row:
            return None
        res = dict(row)
        res["configuration"] = json.loads(res["configuration"]) if res.get("configuration") else {}
        return res

    def list_scans_for_project(self, project_id: str) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        rows = conn.execute(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY started_at DESC",
            (project_id,)
        ).fetchall()
        conn.close()
        res = []
        for r in rows:
            item = dict(r)
            item["configuration"] = json.loads(item["configuration"]) if item.get("configuration") else {}
            res.append(item)
        return res

    # Repository Profile Operations
    def save_profile(self, scan_id: str, languages: Dict[str, int], frameworks: List[str],
                     manifests: List[str], dependencies_summary: List[str],
                     file_count: int, total_bytes: int, warnings: List[str]) -> str:
        pid = uuid.uuid4().hex[:12]
        created = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO repository_profiles "
                "(id, scan_id, languages, frameworks, manifests, dependencies_summary, file_count, total_bytes, warnings, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pid, scan_id, json.dumps(languages), json.dumps(frameworks), json.dumps(manifests),
                 json.dumps(dependencies_summary), file_count, total_bytes, json.dumps(warnings), created)
            )
        conn.close()
        return pid

    def get_profile(self, scan_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT * FROM repository_profiles WHERE scan_id = ?", (scan_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "languages": json.loads(row["languages"]),
            "frameworks": json.loads(row["frameworks"]),
            "manifests": json.loads(row["manifests"]),
            "dependencies_summary": json.loads(row["dependencies_summary"]),
            "file_count": row["file_count"],
            "total_bytes": row["total_bytes"],
            "warnings": json.loads(row["warnings"]),
            "created_at": row["created_at"]
        }

    # Analyzer Run Operations
    def record_analyzer_run(self, scan_id: str, name: str, version: str,
                            status: str, exit_code: Optional[int] = None,
                            error_summary: Optional[str] = None) -> str:
        aid = uuid.uuid4().hex[:12]
        now = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT INTO analyzer_runs (id, scan_id, analyzer_name, analyzer_version, status, "
                "started_at, completed_at, exit_code, error_summary) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (aid, scan_id, name, version, status, now, now, exit_code, error_summary)
            )
        conn.close()
        return aid

    def list_analyzer_runs(self, scan_id: str) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        rows = conn.execute("SELECT * FROM analyzer_runs WHERE scan_id = ?", (scan_id,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # Finding & Evidence Operations
    def save_finding(self, scan_id: str, stable_fingerprint: str, rule_id: str,
                     title: str, description: str, severity: str, confidence: float,
                     file_path: str, start_line: int, end_line: int,
                     evidence_excerpt_redacted: str, remediation: str,
                     cwe: Optional[str] = None,
                     lifecycle_status: str = "needs_review",
                     finding_id: Optional[str] = None) -> str:
        fid = finding_id or uuid.uuid4().hex[:12]
        created = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO findings (id, scan_id, stable_fingerprint, rule_id, title, description, "
                "severity, confidence, cwe, file_path, start_line, end_line, "
                "evidence_excerpt_redacted, lifecycle_status, remediation, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fid, scan_id, stable_fingerprint, rule_id, title, description,
                 severity, confidence, cwe, file_path, start_line, end_line,
                 evidence_excerpt_redacted, lifecycle_status, remediation, created)
            )
        conn.close()
        return fid

    def save_evidence(self, finding_id: str, source_type: str, analyzer_reference: str,
                      file_path: str, line_start: int, line_end: int,
                      description: Optional[str] = None, content_hash: Optional[str] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        eid = uuid.uuid4().hex[:12]
        meta_json = json.dumps(metadata or {})
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT INTO evidence (id, finding_id, source_type, analyzer_reference, description, "
                "file_path, line_start, line_end, content_hash, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (eid, finding_id, source_type, analyzer_reference, description or "",
                 file_path, line_start, line_end, content_hash or "", meta_json)
            )
        conn.close()
        return eid

    def save_context_bundle(self, finding_id: str, context_type: str, file_path: str,
                            content_redacted: str, retrieval_method: str,
                            line_start: Optional[int] = None, line_end: Optional[int] = None) -> str:
        cid = uuid.uuid4().hex[:12]
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT INTO context_bundles (id, finding_id, context_type, file_path, line_start, "
                "line_end, content_redacted, retrieval_method) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (cid, finding_id, context_type, file_path, line_start, line_end,
                 content_redacted, retrieval_method)
            )
        conn.close()
        return cid

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT * FROM findings WHERE id = ? OR id LIKE ?", (finding_id, f"%_{finding_id}")).fetchone()
        if not row:
            conn.close()
            return None
        res = dict(row)
        ev_rows = conn.execute("SELECT * FROM evidence WHERE finding_id = ?", (res["id"],)).fetchall()
        res["evidence"] = [dict(e) for e in ev_rows]
        ctx_rows = conn.execute("SELECT * FROM context_bundles WHERE finding_id = ?", (res["id"],)).fetchall()
        res["context_bundles"] = [dict(c) for c in ctx_rows]
        ai_row = conn.execute("SELECT * FROM ai_assessments WHERE finding_id = ?", (res["id"],)).fetchone()
        if ai_row:
            ai_dict = dict(ai_row)
            ai_dict["structured_result"] = json.loads(ai_dict["structured_result"])
            res["ai_assessment"] = ai_dict
        else:
            res["ai_assessment"] = None
        conn.close()
        return res

    def list_findings(self, scan_id: str, severity: Optional[str] = None,
                      status: Optional[str] = None, cwe: Optional[str] = None,
                      file_path: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params = [scan_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())
        if status:
            query += " AND lifecycle_status = ?"
            params.append(status.lower())
        if cwe:
            query += " AND cwe = ?"
            params.append(cwe.upper())
        if file_path:
            query += " AND file_path LIKE ?"
            params.append(f"%{file_path}%")
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, start_line ASC"
        rows = conn.execute(query, tuple(params)).fetchall()
        
        findings = []
        for r in rows:
            f = dict(r)
            evs = conn.execute("SELECT * FROM evidence WHERE finding_id = ?", (f["id"],)).fetchall()
            f["evidence"] = [dict(e) for e in evs]
            ctx = conn.execute("SELECT * FROM context_bundles WHERE finding_id = ?", (f["id"],)).fetchall()
            f["context_bundles"] = [dict(c) for c in ctx]
            findings.append(f)
        conn.close()
        return findings

    def update_finding_status(self, finding_id: str, status: str, actor: str = "reviewer",
                              comment: Optional[str] = None) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT id, scan_id, lifecycle_status FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            conn.close()
            return None
        old_status = row["lifecycle_status"]
        scan_id = row["scan_id"]
        with conn:
            conn.execute("UPDATE findings SET lifecycle_status = ? WHERE id = ?", (status, finding_id))
            scan_row = conn.execute("SELECT project_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
            pid = scan_row["project_id"] if scan_row else None
            self.log_audit(conn, project_id=pid, scan_id=scan_id, event_type="FINDING_STATUS_CHANGED",
                           details={"finding_id": finding_id, "old_status": old_status,
                                    "new_status": status, "comment": comment or ""},
                           actor=actor)
        conn.close()
        return self.get_finding(finding_id)

    # Report Operations
    def save_report(self, scan_id: str, payload: Dict[str, Any], content_hash: str,
                    storage_path: Optional[str] = None) -> str:
        rid = uuid.uuid4().hex[:12]
        now = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports (id, scan_id, format, storage_path, payload, generated_at, content_hash) "
                "VALUES (?, ?, 'json', ?, ?, ?, ?)",
                (rid, scan_id, storage_path or "", json.dumps(payload), now, content_hash)
            )
        conn.close()
        return rid

    def get_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        row = conn.execute("SELECT * FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "format": row["format"],
            "storage_path": row["storage_path"],
            "payload": json.loads(row["payload"]),
            "generated_at": row["generated_at"],
            "content_hash": row["content_hash"]
        }

    # AI Assessment Operations
    def save_ai_assessment(self, finding_id: str, provider: str, model: str,
                           prompt_version: str, verdict: str, structured_result: Dict[str, Any],
                           status: str = "completed") -> str:
        aid = uuid.uuid4().hex[:12]
        now = now_iso()
        conn = self.get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO ai_assessments "
                "(id, finding_id, provider, model, prompt_version, verdict, structured_result, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (aid, finding_id, provider, model, prompt_version, verdict,
                 json.dumps(structured_result), status, now)
            )
        conn.close()
        return aid

    # Audit Logging
    def log_audit(self, conn: sqlite3.Connection, event_type: str, details: Dict[str, Any],
                  project_id: Optional[str] = None, scan_id: Optional[str] = None,
                  actor: str = "system") -> None:
        aid = uuid.uuid4().hex[:12]
        now = now_iso()
        conn.execute(
            "INSERT INTO audit_events (id, project_id, scan_id, actor, event_type, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (aid, project_id, scan_id, actor, event_type, json.dumps(details), now)
        )
