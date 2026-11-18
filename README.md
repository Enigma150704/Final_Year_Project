# AI-Driven Vulnerability Discovery System

**Project ID:** 2026-27-CS-10  
**Institution:** Swami Keshwanand Institute of Technology, Management & Gramothan (SKIT), Jaipur  
**Version:** 1.0.0 (Integrated MVP Milestone)  
**Completion Deadline:** February 2027  

---

## Team Module Ownership

- **Module A — Chaudhari Krishna (23ESKIT038):** Backend & AI Orchestration
- **Module B — Bhavesh Shah (23ESKIT034):** Frontend & Reporting
- **Module C — Gunwant Singh Hada (23ESKIT055):** Security Analysis & Repository Intelligence

---

## System Overview

The **AI-Driven Vulnerability Discovery System** is a defensive, authorization-based platform that profiles software repositories, coordinates multi-language static analyzers, extracts enclosing code context via AST/lexical retrieval, normalizes and deduplicates findings, offers structured AI assessments in offline mock mode, and presents actionable reports with reviewer lifecycle controls.

The system is an **evidence-construction pipeline**, not an LLM that guesses whether code is vulnerable.

---

## Key Capabilities

1. **Safe Archive Intake:** Strict Zip-Slip protection, symlink rejection, file count limits (12,000 files), decompression thresholds (40 MB upload, 250 MB expanded, 10 MB per-file), and SHA-256 provenance hashing.
2. **Repository Profiler:** Analyzes file count, byte size, multi-language distribution (Python, JS, TS, Java, etc.), dependency manifests (`package.json`, `requirements.txt`, `pom.xml`), framework markers (FastAPI, Flask, Django, Express, Spring Boot, React), and candidate entry points without executing code.
3. **Multi-Language Conservative Rules:**
   - **SQL Injection:** Python f-strings / concatenation, JavaScript template literals, Java JDBC statements (CWE-89).
   - **Command Injection:** Python `subprocess shell=True`, JavaScript `child_process.exec`, Java `Runtime.getRuntime().exec` (CWE-78).
   - **Code Execution:** Python `eval`/`exec`, JavaScript `eval`/`Function` (CWE-95).
   - **Path Traversal:** File system access incorporating untrusted request parameters (CWE-22).
   - **Secrets Management:** High-entropy credential patterns with automated redaction in UI, evidence, and logs (CWE-798).
   - **Cross-Site Scripting:** Unsafe DOM assignments like `innerHTML` (CWE-79).
4. **Finding Normalizer & Deduplication:** Canonical fingerprinting merges multi-analyzer duplicate reports into unified records, fuses evidence lists, and preserves all tool provenance references.
5. **AST & Lexical Context Retrieval:** Enclosing function or class identification (AST for Python, lexical parsing fallback for JS/Java) plus surrounding line context with automated secrets redaction.
6. **AI Reasoner (Provider Abstraction):** Strict prompt sandboxing (treating repository text as untrusted data) and deterministic `MockAIProvider` returning structured Pydantic schema validation.
7. **Reviewer Lifecycle Management:** Security reviewers can verify and transition findings across `needs_review`, `candidate`, `confirmed`, `rejected`, `fixed`, and `accepted_risk` with audit records.
8. **Modern Security Dashboard:** Responsive dark-mode interface with live scan stage progress tracking, filterable findings explorer, finding detail drawer, and one-click JSON report export.

---

## Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.11 & 3.14)
- Git

### Local Installation & Run

```bash
# 1. Clone repository and navigate to backend
cd backend

# 2. (Optional) Create virtual environment
python -m venv .venv
# On Windows PowerShell: .venv\Scripts\Activate.ps1
# On Linux/macOS: source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
pip install pytest

# 4. Launch development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- **Dashboard UI:** Open [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Documentation:** Open [http://localhost:8000/docs](http://localhost:8000/docs)

### Run with Docker

```bash
docker compose up --build
```

---

## Running the Test Suite

Execute the complete automated test suite (12 tests covering security, rules, deduplication, AST context, and API integration):

```bash
cd backend
python -m pytest -v
```

---

## REST API Summary

- `GET /health` — Service readiness and timestamp.
- `POST /api/projects` — Create a project (`authorization_acknowledged: true` required).
- `GET /api/projects` — List monitored projects.
- `GET /api/projects/{id}` — Project details.
- `POST /api/projects/{id}/repositories` — Upload repository ZIP archive.
- `POST /api/projects/{id}/scans` — Trigger background scan orchestration.
- `GET /api/scans/{id}` — Real-time scan status, stage (`validating`, `profiling`, `scanning`, `normalizing`, `retrieving_context`, `reporting`, `completed`), and progress percentage.
- `GET /api/scans/{id}/profile` — Repository profile and language breakdown.
- `GET /api/scans/{id}/findings` — Filterable findings (`severity`, `status`, `cwe`, `file_path`).
- `GET /api/findings/{id}` — Full finding details, evidence, and context bundles.
- `PATCH /api/findings/{id}` — Update reviewer lifecycle status.
- `GET /api/scans/{id}/tools` — Analyzer run records and versions.
- `GET /api/scans/{id}/report` — Structured JSON report with SHA-256 provenance hash.
- `POST /api/analyze` — Legacy backward-compatible synchronous analysis endpoint.

---

## Documentation Index

- [PROJECT_STATUS.md](file:///e:/Downloads/AI_Driven_Vulnerability_Discovery_System_MVP/ai-vulnerability-discovery-mvp/PROJECT_STATUS.md) — Implementation status and feature verification.
- [IMPLEMENTATION_LOG.md](file:///e:/Downloads/AI_Driven_Vulnerability_Discovery_System_MVP/ai-vulnerability-discovery-mvp/IMPLEMENTATION_LOG.md) — Chronological engineering log.
- [ARCHITECTURE.md](file:///e:/Downloads/AI_Driven_Vulnerability_Discovery_System_MVP/ai-vulnerability-discovery-mvp/ARCHITECTURE.md) — Component architecture, state machines, and trust boundaries.
- [API_CONTRACT.md](file:///e:/Downloads/AI_Driven_Vulnerability_Discovery_System_MVP/ai-vulnerability-discovery-mvp/API_CONTRACT.md) — Complete REST API specifications.
- [SECURITY.md](file:///e:/Downloads/AI_Driven_Vulnerability_Discovery_System_MVP/ai-vulnerability-discovery-mvp/SECURITY.md) — Security policy, authorization mandate, and threat model.
