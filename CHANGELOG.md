# Changelog

All notable changes to the **AI-Driven Vulnerability Discovery System** are documented in this file.

## [1.0.0] - 2026-11-18

### Added
- **SQLite Relational Persistence Layer (`database.py`):**
  - Full relational tables for `projects`, `repository_snapshots`, `scans`, `repository_profiles`, `analyzer_runs`, `findings`, `evidence`, `context_bundles`, `ai_assessments`, `reports`, and `audit_events`.
  - Transaction safety, WAL mode, foreign key cascades, and query performance indexes.
- **Multi-Language Conservative Rule Engine (`scanner.py`):**
  - Expanded heuristic rules for Python, JavaScript/TypeScript, and Java.
  - Covers SQL Injection, Command Injection, Dynamic Code Execution, Path Traversal, Secrets (redacted), and DOM XSS.
- **Finding Normalizer & Deduplication Engine (`scanner.py`):**
  - Deduplicates multi-analyzer findings using canonical fingerprints.
  - Merges evidence lists and aggregates tool source references.
- **AST Enclosing Scope Retrieval (`retrieval.py`):**
  - Python AST analysis (`ast.parse`) to identify enclosing function/class definitions.
  - Lexical scope fallback for JavaScript and Java.
  - Automatic secrets redaction in all context snippets.
- **AI Reasoner Abstraction (`ai.py`):**
  - Provider-neutral `AIProvider` interface.
  - Deterministic `MockAIProvider` with Pydantic structured output validation (`AIAssessmentResult`).
  - Strict untrusted input boundary against prompt injection.
- **Scan Lifecycle Orchestrator (`orchestrator.py`):**
  - Stateful execution with stage transitions: `queued` → `validating` → `profiling` → `scanning` → `normalizing` → `retrieving_context` → `reporting` → `completed`.
- **Complete REST API Contract (`main.py`):**
  - 13 REST endpoints conforming to Blueprint Section 8.
  - Reviewer lifecycle status updates (`PATCH /api/findings/{id}`).
  - Maintained 100% backward compatibility for `/api/analyze`.
- **Modern Responsive Security Dashboard (`frontend/index.html`):**
  - Dark-mode professional security UI.
  - Project management, explicit authorization checkbox, live progress tracker.
  - Filterable findings explorer, finding detail drawer with reviewer controls, and one-click JSON report download.
- **Comprehensive Integration Test Suite:**
  - 12 automated unit and integration tests across safe extraction, profiling, rules, deduplication, AST context, API lifecycle, reviewer PATCH, and reports.
- **Project Documentation Suite:**
  - `PROJECT_STATUS.md`, `IMPLEMENTATION_LOG.md`, `ARCHITECTURE.md`, `API_CONTRACT.md`, `SECURITY.md`, `.env.example`, `CHANGELOG.md`.

