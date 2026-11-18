# Security Policy & Defensive Model

**Project ID:** 2026-27-CS-10  
**Project Title:** AI-Driven Vulnerability Discovery System  
**Institution:** Swami Keshwanand Institute of Technology, Management & Gramothan (SKIT), Jaipur  

---

## 1. Defensive Authorization Mandate

This system is built exclusively for authorized security reviews of codebases that the user owns or has explicit written authorization to analyze.
- Every project requires an explicit `authorization_acknowledged: true` confirmation before any archive can be accepted or analyzed.
- The system rejects unauthorized scans with `400 Bad Request`.
- Internet-wide scanning, unconsented target discovery, exploit chaining, and credential harvesting are strictly out of scope.

---

## 2. Archive Ingestion Hardening (Zip-Slip & Decompression Bomb Protection)

All uploaded archives are treated as hostile binary input:
1. **Directory Traversal Prevention:** Target file paths are strictly canonicalized (`PurePosixPath`). Any archive member with `..`, absolute paths, drive letters, or resolving outside the isolated snapshot extraction root is immediately rejected with a `ValueError`.
2. **Symlink and Device File Rejection:** Archive entries are inspected against Unix file mode bits (`mode & 0o170000`). Symlinks, hardlinks, named pipes, and character/block devices are forbidden and rejected.
3. **Decompression Limits:**
   - Maximum upload size: 40 MB
   - Maximum uncompressed total size: 250 MB
   - Maximum uncompressed single-file size: 10 MB
   - Maximum file count: 12,000 files
   - Streaming read validation prevents memory exhaustion.

---

## 3. Safe Execution Boundaries

- **Static Analysis Only:** The system does not run application code, build scripts (`build.gradle`, `pom.xml`, `setup.py`), package installation hooks, or automated test runners from the target repository.
- **Subprocess Isolation:** Analyzers (such as optional Semgrep) are executed with argument lists (`shell=False`), fixed command templates, timeouts (180s), and bounded JSON output capture.
- **Redaction of Discovered Secrets:** Any high-entropy token or credential detected by the `GEN-SECRET` rule is sanitized in memory using `redact_secret_text`. Cleartext credentials are never saved to SQLite, exported to reports, or logged to disk.
- **Prompt Injection Defense:** AI prompts explicitly isolate repository code inside demarcated blocks and instruct the model to ignore instructions found within user code, README files, or comments.

