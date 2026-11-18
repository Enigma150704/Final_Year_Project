# API Contract

**Project ID:** 2026-27-CS-10  
**Project Title:** AI-Driven Vulnerability Discovery System  
**Version:** 1.0.0  
**Base URL:** `http://localhost:8000`  
**OpenAPI Documentation:** `http://localhost:8000/docs`

---

## Endpoints Summary

| Method | Path | Description | Status Code |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Service health status and ISO timestamp | 200 OK |
| `POST` | `/api/projects` | Create a new project (requires `authorization_acknowledged: true`) | 201 Created |
| `GET` | `/api/projects` | List all monitored projects with scan summaries | 200 OK |
| `GET` | `/api/projects/{project_id}` | Retrieve details for a specific project | 200 OK |
| `POST` | `/api/projects/{project_id}/repositories` | Upload a repository ZIP snapshot | 200 OK |
| `POST` | `/api/projects/{project_id}/scans` | Start an analysis scan for the project's repository snapshot | 202 Accepted |
| `GET` | `/api/scans/{scan_id}` | Check scan status, stage, progress (0-100%), and errors | 200 OK |
| `GET` | `/api/scans/{scan_id}/profile` | Retrieve repository profile (languages, frameworks, manifests) | 200 OK |
| `GET` | `/api/scans/{scan_id}/findings` | Retrieve findings with optional filters (`severity`, `status`, `cwe`, `file_path`) | 200 OK |
| `GET` | `/api/findings/{finding_id}` | Retrieve finding details, evidence, context bundles, and AI assessment | 200 OK |
| `PATCH` | `/api/findings/{finding_id}` | Update reviewer lifecycle status (`needs_review`, `confirmed`, `rejected`, etc.) | 200 OK |
| `GET` | `/api/scans/{scan_id}/tools` | List analyzer runs (status, tool versions, exit codes) | 200 OK |
| `GET` | `/api/scans/{scan_id}/report` | Retrieve formal scan JSON report with SHA-256 provenance hash | 200 OK |
| `POST` | `/api/scans/{scan_id}/cancel` | Cancel an ongoing scan | 200 OK |
| `POST` | `/api/analyze` | Legacy synchronous analysis endpoint (backward-compatible) | 200 OK |

---

## Key Payloads

### 1. `POST /api/projects`
```json
{
  "name": "E-Commerce Core",
  "description": "Payment microservice",
  "authorization_acknowledged": true
}
```

### 2. `POST /api/projects/{id}/scans`
```json
{
  "snapshot_id": "optional_snapshot_id",
  "configuration": {
    "enable_ai": true
  }
}
```

### 3. `PATCH /api/findings/{id}`
```json
{
  "lifecycle_status": "confirmed",
  "comment": "Verified user parameter flows directly into SQL execution sink.",
  "actor": "security-analyst"
}
```

