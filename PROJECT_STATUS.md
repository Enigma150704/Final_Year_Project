# Project Implementation Status

**Project ID:** 2026-27-CS-10  
**Project Title:** AI-Driven Vulnerability Discovery System  
**Institution:** Swami Keshwanand Institute of Technology, Management & Gramothan (SKIT), Jaipur  
**Completion Deadline:** February 2027 (October 2026: Intermediate Integrated-MVP Milestone)  
**Last Updated:** November 2026  

---

## Team Module Ownership

- **Module A — Chaudhari Krishna (23ESKIT038):** Backend & AI Orchestration
- **Module B — Bhavesh Shah (23ESKIT034):** Frontend & Reporting
- **Module C — Gunwant Singh Hada (23ESKIT055):** Security Analysis & Repository Intelligence

---

## Feature Matrix & Implementation Evidence

| Feature | Module | Status | Evidence & Test Results |
| :--- | :---: | :---: | :--- |
| **Defensive Authorization Enforcement** | A / B | **Implemented** | Rejects unconfirmed requests (`400 Bad Request`); checkbox in UI required. Tested in `test_api_integration.py::test_project_creation_and_authorization_enforcement`. |
| **Safe Archive Intake (Zip-Slip & Bomb Protection)** | C / A | **Implemented** | `safe_extract_zip_with_metadata` enforces 40MB upload limit, 250MB uncompressed limit, 10MB per-file limit, 12,000 files, path normalization, and rejection of absolute paths, symlinks, and traversal. Verified in `test_security.py` & `test_analysis_engine.py`. |
| **SHA-256 Provenance Hashing** | C / A | **Implemented** | Cryptographic SHA-256 computed on upload and stored in `repository_snapshots.content_hash` and reports. Verified in `test_analysis_engine.py::test_safe_zip_metadata_and_hash`. |
| **Repository Profiler** | C | **Implemented** | File inventory, multi-language detection (Python, JS, TS, Java, etc.), framework markers (FastAPI, Flask, Django, Express, Spring Boot, React), dependency manifests, entry points. Verified in `test_api_integration.py::test_full_scan_lifecycle_and_reviewer_workflow`. |
| **Multi-Language Conservative Rule Engine** | C | **Implemented** | Conservative rules for SQL Injection (f-string, concat, template literals, JDBC), Command Injection (`shell=True`, `child_process.exec`, `Runtime.getRuntime().exec`), Code Execution (`eval`/`exec`, `Function`), Path Traversal, Secrets (redacted), and XSS (`innerHTML`). Verified in `test_analysis_engine.py`. |
| **Finding Deduplication & Merging** | C | **Implemented** | Canonical fingerprinting merges multi-analyzer duplicate reports, fuses evidence, and retains all tool references. Verified in `test_analysis_engine.py::test_finding_deduplication`. |
| **AST & Lexical Context Retrieval** | C | **Implemented** | Python AST (`ast.parse`) extracts enclosing function/class; lexical fallback for JS/Java; surrounding lines (+/- 6) with secret redaction. Verified in `test_analysis_engine.py::test_context_retrieval_ast_scope`. |
| **SQLite Persistent Data Store** | A | **Implemented** | Full relational schema for `projects`, `repository_snapshots`, `scans`, `repository_profiles`, `analyzer_runs`, `findings`, `evidence`, `context_bundles`, `ai_assessments`, `reports`, `audit_events`. Verified across all 12 test suites. |
| **Scan Lifecycle State Machine** | A | **Implemented** | Explicit stages: `queued` → `validating` → `profiling` → `scanning` → `normalizing` → `retrieving_context` → `reporting` → `completed` (or `failed`/`cancelled`). Real-time progress percentage tracking. |
| **REST API & OpenAPI Specification** | A | **Implemented** | All 13 Blueprint endpoints implemented: projects, snapshots, scans, filterable findings, reviewer lifecycle updates (`PATCH`), tool statuses, JSON reports, plus legacy compatibility. Verified in `test_api_integration.py`. |
| **Reviewer Lifecycle Management** | A / B | **Implemented** | Security reviewers can transition findings between `needs_review`, `candidate`, `confirmed`, `rejected`, `fixed`, `accepted_risk` with audit logging. Verified in `test_api_integration.py`. |
| **AI Reasoner Provider Abstraction** | A | **Implemented** | `AIProvider` base class and deterministic `MockAIProvider` returning structured Pydantic schema validation (`verdict`, `root_cause`, `preconditions`, `remediation`, `regression_test_idea`). Verified in `test_full_scan_lifecycle_and_reviewer_workflow`. |
| **Responsive Security Dashboard** | B | **Implemented** | Professional UI with project cards, real-time stage progress bar, filterable findings explorer, finding detail drawer with reviewer selector, and one-click JSON report export. Tested in `frontend/index.html`. |
| **Graceful Tool Degradation** | C / A | **Implemented** | Semgrep check is cached and optional; missing Semgrep reports tool as unavailable/skipped without crashing scan. Verified in test runs. |

---

## Planned Future Milestones

- [ ] **November 2026:** PostgreSQL persistence driver option and database migration runner.
- [ ] **December 2026:** Real LLM integration (Gemini / Claude / OpenAI) behind the existing `AIProvider` interface with live API keys and prompt sandboxing.
- [ ] **January 2027:** Tree-sitter multi-language AST/symbol indexer and taint graph analysis; isolated sandbox validation runner with default-deny network policy.
- [ ] **February 2027:** Benchmark evaluation suite (NIST SARD/Juliet, OWASP WebGoat/JuiceShop), precision/recall metrics, PDF export, final project demonstration.
