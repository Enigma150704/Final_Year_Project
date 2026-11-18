from pathlib import Path
import re
import hashlib
import json
import shutil
import subprocess
import tempfile
import functools
from typing import List, Tuple, Dict, Any, Optional

from .security import is_source_file, should_ignore, redact_secret_text
from .models import Finding, Evidence

MAX_FILE_BYTES = 500_000

# Multi-language conservative rules with CWE mapping, confidence, and remediation
RULES = [
    # --- Python Vulnerability Candidates ---
    {
        "id": "PY-SQL-FSTRING",
        "language": "python",
        "title": "Possible SQL injection via dynamic f-string query",
        "severity": "high",
        "confidence": 0.72,
        "cwe": "CWE-89",
        "category": "Injection",
        "regex": r"(?:execute|executemany)\s*\(\s*f[\"']",
        "description": "SQL query built with an f-string passed directly to an execution call. If untrusted input is interpolated, attackers can manipulate the SQL query structure.",
        "remediation": "Use parameterized queries or ORM query builders. Never interpolate variables directly into SQL statements."
    },
    {
        "id": "PY-SQL-CONCAT",
        "language": "python",
        "title": "Possible SQL injection via string concatenation",
        "severity": "high",
        "confidence": 0.68,
        "cwe": "CWE-89",
        "category": "Injection",
        "regex": r"(?:execute|executemany)\s*\(\s*[^,\n]*\s*\+\s*",
        "description": "Database query constructed using string concatenation (+). Verify whether untrusted request parameters reach this query.",
        "remediation": "Replace string concatenation with parameterized statements using bound query arguments (?, %s, or :named)."
    },
    {
        "id": "PY-SHELL-TRUE",
        "language": "python",
        "title": "Subprocess execution with shell=True",
        "severity": "high",
        "confidence": 0.66,
        "cwe": "CWE-78",
        "category": "Command Injection",
        "regex": r"(?:subprocess\.(?:run|Popen|call|check_output))\s*\([^)]*shell\s*=\s*True",
        "description": "Subprocess invoked with shell=True enables system command shell parsing. If arguments contain user-controlled input, command injection is possible.",
        "remediation": "Pass commands as an argument list (e.g. ['executable', 'arg1']) with shell=False. Validate all arguments against strict allowlists."
    },
    {
        "id": "PY-EVAL",
        "language": "python",
        "title": "Dynamic code execution via eval/exec",
        "severity": "high",
        "confidence": 0.60,
        "cwe": "CWE-95",
        "category": "Code Injection",
        "regex": r"\b(?:eval|exec)\s*\(",
        "description": "Dynamic code execution found. If evaluated content incorporates untrusted external input, arbitrary code execution may occur.",
        "remediation": "Avoid eval() and exec(). Use ast.literal_eval() for safe literal data or explicit dispatched handler maps."
    },
    {
        "id": "PY-PATH-TRAVERSAL",
        "language": "python",
        "title": "Possible path traversal in file operation",
        "severity": "medium",
        "confidence": 0.52,
        "cwe": "CWE-22",
        "category": "Path Traversal",
        "regex": r"(?:open|Path|read_text|write_text)\s*\([^)\n]*(?:request\.|query_params|params\[|args\.get)",
        "description": "File system access appears to incorporate request-derived parameters without visible path validation.",
        "remediation": "Resolve paths against a fixed base directory with Path.resolve() and verify the resolved path remains within the intended root folder."
    },

    # --- JavaScript / TypeScript Vulnerability Candidates ---
    {
        "id": "JS-SQL-TEMPLATE",
        "language": "javascript",
        "title": "Possible SQL injection in JavaScript/TypeScript query",
        "severity": "high",
        "confidence": 0.70,
        "cwe": "CWE-89",
        "category": "Injection",
        "regex": r"(?:\.query|\.execute)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`",
        "description": "Database query constructed using template literals (${...}). Untrusted input interpolated into SQL can lead to database compromise.",
        "remediation": "Use parameterized queries with placeholder arrays (e.g. db.query('SELECT * FROM t WHERE id = $1', [id]))."
    },
    {
        "id": "JS-COMMAND-EXEC",
        "language": "javascript",
        "title": "Command injection via child_process execution",
        "severity": "high",
        "confidence": 0.68,
        "cwe": "CWE-78",
        "category": "Command Injection",
        "regex": r"(?:child_process|cp)\.(?:exec|execSync)\s*\(",
        "description": "child_process.exec() passes commands to a system shell. Untrusted arguments allow shell command chaining.",
        "remediation": "Use child_process.execFile() or spawn() with argument arrays and shell: false."
    },
    {
        "id": "JS-EVAL-CODE",
        "language": "javascript",
        "title": "Dynamic code evaluation via eval / Function",
        "severity": "high",
        "confidence": 0.62,
        "cwe": "CWE-95",
        "category": "Code Injection",
        "regex": r"\b(?:eval\s*\(|new\s+Function\s*\()",
        "description": "JavaScript dynamic evaluation through eval() or Function constructor creates code injection risks.",
        "remediation": "Avoid eval() and Function constructor. Use JSON.parse() for structured data or declarative parsing."
    },
    {
        "id": "JS-XSS-INNERHTML",
        "language": "javascript",
        "title": "Potential DOM XSS via innerHTML / dangerouslySetInnerHTML",
        "severity": "medium",
        "confidence": 0.58,
        "cwe": "CWE-79",
        "category": "Cross-Site Scripting",
        "regex": r"(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*=)",
        "description": "Direct assignment to innerHTML or dangerouslySetInnerHTML can execute malicious scripts if unsanitized user content is rendered.",
        "remediation": "Use textContent or safe DOM creation APIs. If HTML rendering is mandatory, sanitize with DOMPurify."
    },

    # --- Java Vulnerability Candidates ---
    {
        "id": "JAVA-SQL-CONCAT",
        "language": "java",
        "title": "Possible SQL injection in Java JDBC Statement",
        "severity": "high",
        "confidence": 0.70,
        "cwe": "CWE-89",
        "category": "Injection",
        "regex": r"(?:executeQuery|executeUpdate|createQuery)\s*\(\s*[^,\n]*\s*\+\s*",
        "description": "Java database execution call using string concatenation. Untrusted input concatenated into SQL creates injection risk.",
        "remediation": "Use java.sql.PreparedStatement with positional parameters (?) or JPA parameterized queries."
    },
    {
        "id": "JAVA-COMMAND-EXEC",
        "language": "java",
        "title": "Command execution via Runtime.exec or ProcessBuilder",
        "severity": "high",
        "confidence": 0.65,
        "cwe": "CWE-78",
        "category": "Command Injection",
        "regex": r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(",
        "description": "Java system command execution. If any command token comes from untrusted user input, command injection can occur.",
        "remediation": "Avoid calling system shells directly. Pass individual arguments as a List and enforce strict argument validation."
    },

    # --- Generic Multi-Language Rules ---
    {
        "id": "GEN-SECRET",
        "language": "generic",
        "title": "Possible hard-coded credential or secret token",
        "severity": "high",
        "confidence": 0.62,
        "cwe": "CWE-798",
        "category": "Secrets Management",
        "regex": r"(?i)\b(?:api[_-]?key|secret|password|access_token|private_key)\b\s*[:=]\s*[\"'][A-Za-z0-9_\-./+=]{12,}[\"']",
        "description": "A credential-like variable is assigned a hard-coded string. The value has been redacted in evidence.",
        "remediation": "Store credentials in environment variables or an enterprise secrets vault (e.g. AWS Secrets Manager, HashiCorp Vault). Rotate any committed credentials."
    },
    {
        "id": "GEN-PATH",
        "language": "generic",
        "title": "Potential path traversal in file operation",
        "severity": "medium",
        "confidence": 0.50,
        "cwe": "CWE-22",
        "category": "Path Traversal",
        "regex": r"(?:open|readFile|createReadStream|new\s+File)\s*\([^)\n]*(?:request\.|req\.query|req\.params|args\.get|getParameter)",
        "description": "File system access appears to incorporate request parameters. Verify that path canonicalization and directory boundary checks are performed.",
        "remediation": "Sanitize input, strip directory traversal characters, and verify the canonical path is within the target directory."
    }
]

def _stable_fingerprint(rule_id: str, cwe: Optional[str], path: str, start_line: int, end_line: int) -> str:
    """Generate a stable, reproducible fingerprint for finding deduplication."""
    norm_path = path.replace("\\", "/").lower()
    cwe_tag = (cwe or rule_id).upper()
    # Group nearby lines within a 3-line window to catch minor line offsets
    norm_line = start_line // 3
    raw = f"{cwe_tag}:{norm_path}:{norm_line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def _finding_id(rule_id: str, path: str, line: int, redacted_text: str) -> str:
    """Generate a clean finding ID without hashing raw unredacted secret values."""
    norm_path = path.replace("\\", "/").lower()
    clean_sample = redacted_text.strip()[:100]
    raw = f"{rule_id}:{norm_path}:{line}:{clean_sample}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]

def _line_excerpt(lines: List[str], idx: int, is_secret: bool = False) -> Tuple[int, int, str]:
    start = max(0, idx - 2)
    end = min(len(lines), idx + 3)
    excerpt_lines = [f"{i+1}: {lines[i]}" for i in range(start, end)]
    excerpt = "\n".join(excerpt_lines)
    if is_secret:
        excerpt = redact_secret_text(excerpt)
    return start + 1, end, excerpt

def builtin_scan(repo: Path) -> List[Finding]:
    """Run conservative built-in heuristic rules against repository source files."""
    findings: List[Finding] = []
    
    for path in repo.rglob("*"):
        if not is_source_file(path) or should_ignore(path.relative_to(repo)):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = content.splitlines()
        rel = str(path.relative_to(repo)).replace("\\", "/")
        ext = path.suffix.lower()

        for rule in RULES:
            # Language filtering where applicable
            lang = rule.get("language", "generic")
            if lang == "python" and ext != ".py":
                continue
            if lang == "javascript" and ext not in (".js", ".jsx", ".ts", ".tsx"):
                continue
            if lang == "java" and ext != ".java":
                continue

            rx = re.compile(rule["regex"])
            is_secret = (rule["id"] == "GEN-SECRET")
            
            for idx, line in enumerate(lines):
                if rx.search(line):
                    start_l, end_l, excerpt = _line_excerpt(lines, idx, is_secret)
                    redacted_line = redact_secret_text(line) if is_secret else line
                    fid = _finding_id(rule["id"], rel, idx + 1, redacted_line)
                    fingerprint = _stable_fingerprint(rule["id"], rule["cwe"], rel, idx + 1, idx + 1)
                    
                    findings.append(Finding(
                        finding_id=fid,
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        cwe=rule["cwe"],
                        category=rule["category"],
                        file=rel,
                        start_line=idx + 1,
                        end_line=idx + 1,
                        evidence=[Evidence(
                            file=rel,
                            start_line=start_l,
                            end_line=end_l,
                            excerpt=excerpt,
                            source=f"builtin:{rule['id']}"
                        )],
                        remediation=rule["remediation"],
                        source=f"builtin:{rule['id']}",
                        status="needs_review",
                        stable_fingerprint=fingerprint
                    ))
    return findings

@functools.lru_cache(maxsize=1)
def semgrep_available() -> bool:
    """Check if Semgrep CLI is installed in PATH."""
    return shutil.which("semgrep") is not None

def run_semgrep(repo: Path) -> Tuple[List[Finding], Optional[str]]:
    """Execute Semgrep with timeout and safe bounded output parsing."""
    if not semgrep_available():
        return [], "Semgrep is not installed in the environment."

    with tempfile.TemporaryDirectory() as td:
        out_file = Path(td) / "semgrep.json"
        cmd = [
            "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--output", str(out_file),
            str(repo)
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
                cwd=str(repo)
            )
            raw: Dict[str, Any] = {}
            if out_file.exists():
                try:
                    raw = json.loads(out_file.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    raw = {}
            elif proc.stdout.strip().startswith("{"):
                try:
                    raw = json.loads(proc.stdout)
                except Exception:
                    raw = {}

            findings: List[Finding] = []
            for item in raw.get("results", []):
                extra = item.get("extra", {})
                raw_path = item.get("path", "unknown")
                # Normalize relative path
                try:
                    p_obj = Path(raw_path)
                    if p_obj.is_absolute():
                        rel_path = str(p_obj.relative_to(repo.resolve())).replace("\\", "/")
                    else:
                        rel_path = raw_path.replace("\\", "/")
                except Exception:
                    rel_path = raw_path.replace("\\", "/")

                start = item.get("start", {}).get("line", 1)
                end = item.get("end", {}).get("line", start)
                lines = redact_secret_text(extra.get("lines", ""))
                sev = (extra.get("severity") or "WARNING").lower()
                severity = "critical" if sev == "error" else "medium" if sev == "warning" else "low"
                
                check_id = item.get("check_id", "semgrep")
                # Extract potential CWE from Semgrep metadata
                meta = extra.get("metadata", {})
                cwe_val = None
                cwe_raw = meta.get("cwe")
                if isinstance(cwe_raw, list) and cwe_raw:
                    cwe_val = str(cwe_raw[0]).split(":")[0].strip()
                elif isinstance(cwe_raw, str):
                    cwe_val = cwe_raw.split(":")[0].strip()

                fingerprint = _stable_fingerprint(check_id, cwe_val, rel_path, start, end)
                fid = _finding_id(check_id, rel_path, start, lines)

                findings.append(Finding(
                    finding_id=fid,
                    title=extra.get("message", check_id)[:180],
                    description=extra.get("message", "Semgrep identified a potential security issue."),
                    severity=severity,
                    confidence=0.65,
                    cwe=cwe_val,
                    category=meta.get("category", "Semgrep Rule"),
                    file=rel_path,
                    start_line=start,
                    end_line=end,
                    evidence=[Evidence(
                        file=rel_path,
                        start_line=start,
                        end_line=end,
                        excerpt=lines[:2000],
                        source=f"semgrep:{check_id}"
                    )],
                    remediation="Review data flow and ensure proper input validation and sanitization.",
                    source=f"semgrep:{check_id}",
                    status="needs_review",
                    stable_fingerprint=fingerprint
                ))
            
            warning = None
            if proc.returncode not in (0, 1):
                warning = f"Semgrep returned exit code {proc.returncode}."
            return findings, warning

        except subprocess.TimeoutExpired:
            return [], "Semgrep scan timed out after 180 seconds."
        except Exception as exc:
            return [], f"Semgrep adapter execution error: {type(exc).__name__}"

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate findings from multiple analyzers matching on file, CWE/category, and line proximity.
    Fuses evidence lists and retains all analyzer references.
    """
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    grouped: Dict[str, List[Finding]] = {}

    for f in findings:
        fp = f.stable_fingerprint or _stable_fingerprint(f.source, f.cwe, f.file, f.start_line, f.end_line)
        if fp not in grouped:
            grouped[fp] = []
        grouped[fp].append(f)

    deduped: List[Finding] = []
    for fp, items in grouped.items():
        if len(items) == 1:
            deduped.append(items[0])
            continue

        # Sort by highest severity and confidence
        items.sort(key=lambda x: (severity_rank.get(x.severity, 0), x.confidence), reverse=True)
        primary = items[0]

        # Merge evidence and sources
        all_evidence: List[Evidence] = []
        seen_evidence = set()
        sources = []
        for it in items:
            if it.source not in sources:
                sources.append(it.source)
            for ev in it.evidence:
                ev_key = (ev.file, ev.start_line, ev.end_line)
                if ev_key not in seen_evidence:
                    seen_evidence.add(ev_key)
                    all_evidence.append(ev)

        merged = Finding(
            finding_id=primary.finding_id,
            title=primary.title,
            description=primary.description,
            severity=primary.severity,
            confidence=max(it.confidence for it in items),
            cwe=primary.cwe or next((it.cwe for it in items if it.cwe), None),
            category=primary.category,
            file=primary.file,
            start_line=primary.start_line,
            end_line=primary.end_line,
            evidence=all_evidence,
            remediation=primary.remediation,
            source=", ".join(sources),
            status=primary.status,
            stable_fingerprint=fp
        )
        deduped.append(merged)

    return deduped

def scan_repository(repo: Path) -> Tuple[List[Finding], str, List[str]]:
    """
    Main scanner orchestration:
    Runs Semgrep (if available) + conservative built-in rules, then deduplicates findings.
    """
    raw_findings: List[Finding] = []
    warnings: List[str] = []
    mode = "built-in rules"

    if semgrep_available():
        semgrep_findings, semgrep_warn = run_semgrep(repo)
        raw_findings.extend(semgrep_findings)
        if semgrep_warn:
            warnings.append(semgrep_warn)
        mode = "semgrep + built-in rules"
    else:
        warnings.append("Semgrep is not installed in the backend environment. Using built-in rule engine.")

    # Built-in rules run as foundational or complementary signal
    builtin_findings = builtin_scan(repo)
    raw_findings.extend(builtin_findings)

    # Normalize and deduplicate
    final_findings = deduplicate_findings(raw_findings)
    return final_findings, mode, warnings
