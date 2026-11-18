# Implementation Log

**Project ID:** 2026-27-CS-10  
**Project Title:** AI-Driven Vulnerability Discovery System  
**Institution:** Swami Keshwanand Institute of Technology, Management & Gramothan (SKIT), Jaipur  

---

## 2026-11-18 — Integrated MVP Architecture & Complete Vertical Slice

### Context & Goal
Upgraded the initial starter prototype to match the full Blueprint specifications across Module A (Chaudhari Krishna), Module B (Bhavesh Shah), and Module C (Gunwant Singh Hada) without disrupting existing working behavior.

### Changes Implemented

1. **Persistence & Shared Contracts (`backend/app/database.py`, `backend/app/models.py`)**
   - Created SQLite persistent relational schema with indexed tables: `projects`, `repository_snapshots`, `scans`, `repository_profiles`, `analyzer_runs`, `findings`, `evidence`, `context_bundles`, `ai_assessments`, `reports`, and `audit_events`.
   - Thread-safe connection handling, WAL mode, foreign key enforcement.
   - Pydantic v2 schemas for all requests, responses, lifecycle states (`LifecycleStatus`), scan stages (`ScanStage`), and structured AI output (`AIAssessmentResult`).

2. **Security & Intake Intelligence (`backend/app/security.py`)**
   - Hardened `safe_extract_zip_with_metadata`: added SHA-256 calculation, Windows and Unix path normalization, Zip-Slip rejection (`..`, absolute paths, drive letters), bomb limits (250MB total, 10MB per-file, 12,000 files).
   - Added regex-based secret redactor (`redact_secret_text`) to mask sensitive credentials in UI, evidence excerpts, and audit logs.

3. **Multi-Language Analysis Engine & Deduplication (`backend/app/scanner.py`)**
   - Expanded conservative rules across Python, JavaScript/TypeScript, and Java:
     - SQL Injection: f-strings (`PY-SQL-FSTRING`), concatenation (`PY-SQL-CONCAT`), template literals (`JS-SQL-TEMPLATE`), JDBC concatenation (`JAVA-SQL-CONCAT`).
     - Command Injection: `subprocess shell=True` (`PY-SHELL-TRUE`), `child_process.exec` (`JS-COMMAND-EXEC`), `Runtime.exec` (`JAVA-COMMAND-EXEC`).
     - Code Execution: `eval`/`exec` (`PY-EVAL`), JS `eval`/`Function` (`JS-EVAL-CODE`).
     - Path Traversal: user parameter concatenation in file calls (`PY-PATH-TRAVERSAL`, `GEN-PATH`).
     - Secrets: high-entropy credential assignments with mandatory redaction (`GEN-SECRET`).
     - Cross-Site Scripting: DOM injection (`JS-XSS-INNERHTML`).
   - Implemented canonical fingerprinting and deduplication (`deduplicate_findings`) to fuse multi-analyzer matches and merge evidence lists.
   - Added `@functools.lru_cache` to `semgrep_available()` to prevent repeated PATH lookups.

4. **AST Context Retrieval (`backend/app/retrieval.py`)**
   - Added `_extract_python_enclosing_scope` using Python `ast.parse` to extract the enclosing function or class for any flagged line.
   - Added `_extract_lexical_enclosing_scope` as a graceful fallback for JavaScript and Java.
   - Bounded context extraction with secrets redaction.

5. **AI Reasoner Provider (`backend/app/ai.py`)**
   - Defined abstract `AIProvider` base class.
   - Implemented `MockAIProvider` returning structured `AIAssessmentResult` validation.
   - Added strict prompt isolation boundaries (treating all repository code as untrusted input).

6. **Scan Lifecycle Orchestrator & REST API (`backend/app/orchestrator.py`, `backend/app/main.py`)**
   - State machine with stage-by-stage progress updates: `queued` → `validating` → `profiling` → `scanning` → `normalizing` → `retrieving_context` → `reporting` → `completed`.
   - Full REST endpoints implemented:
     - `GET /health`
     - `POST /api/projects`, `GET /api/projects`, `GET /api/projects/{id}`
     - `POST /api/projects/{id}/repositories` (enforces authorization)
     - `POST /api/projects/{id}/scans` (background task execution)
     - `GET /api/scans/{id}`, `GET /api/scans/{id}/profile`, `GET /api/scans/{id}/findings`, `GET /api/scans/{id}/tools`
     - `GET /api/findings/{id}`, `PATCH /api/findings/{id}` (reviewer lifecycle state update)
     - `GET /api/scans/{id}/report`
     - Preserved backwards compatibility for legacy `POST /api/analyze`.

7. **Frontend Dashboard & Reviewer Interface (`frontend/index.html`)**
   - Clean, modern security dashboard with dark theme.
   - Project cards, project creation form with authorization checkbox.
   - Real-time scan stage progress tracker with polling.
   - Filterable Findings Explorer (by severity, status, search keyword).
   - Finding detail modal/drawer with enclosed function scope, redacted evidence, remediation, AI assessment, and reviewer status selector.
   - One-click JSON report download.

8. **Test Suite (`backend/tests/`)**
   - Created `tests/test_analysis_engine.py` (vulnerable/safe Python, JS, Java fixtures, deduplication, AST scope, safe ZIP).
   - Created `tests/test_api_integration.py` (project creation, authorization rejection, scan lifecycle, reviewer status PATCH, tool status, JSON report, legacy analyze).
   - All 12 tests passing in test runner.

