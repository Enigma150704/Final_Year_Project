import io
import zipfile
from pathlib import Path
import pytest
from app.scanner import builtin_scan, deduplicate_findings
from app.models import Finding, Evidence
from app.retrieval import retrieve_context
from app.profiler import profile_repository
from app.security import safe_extract_zip_with_metadata, compute_sha256, redact_secret_text

def test_python_vulnerable_and_safe_patterns(tmp_path):
    # Vulnerable Python file
    vuln_py = tmp_path / "vuln.py"
    vuln_py.write_text("""
import subprocess
import os

def handle_user(user_id, raw_cmd):
    # SQL injection f-string
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # Command injection shell=True
    subprocess.run(raw_cmd, shell=True)
    # Dynamic eval
    eval(raw_cmd)
    # Hardcoded secret
    api_key = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
""")

    # Safe Python file
    safe_py = tmp_path / "safe.py"
    safe_py.write_text("""
import subprocess
import ast

def safe_handler(user_id, safe_cmd):
    # Parameterized SQL query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    # Safe subprocess execution with argument list
    subprocess.run(["ls", "-l"], shell=False)
    # Safe literal evaluation
    ast.literal_eval(safe_cmd)
""")

    findings = builtin_scan(tmp_path)
    cwes = [f.cwe for f in findings]
    
    assert "CWE-89" in cwes  # SQL injection detected
    assert "CWE-78" in cwes  # Command injection detected
    assert "CWE-95" in cwes  # Dynamic code execution detected
    assert "CWE-798" in cwes # Secret detected

    # Verify secret is redacted in evidence and excerpt
    secret_findings = [f for f in findings if f.cwe == "CWE-798"]
    assert len(secret_findings) > 0
    assert "AIzaSyD" not in secret_findings[0].evidence[0].excerpt
    assert "[REDACTED]" in secret_findings[0].evidence[0].excerpt

def test_javascript_and_java_rules(tmp_path):
    js_file = tmp_path / "server.js"
    js_file.write_text("""
const cp = require('child_process');
function run(input) {
    db.query(`SELECT * FROM accounts WHERE name = '${input}'`);
    cp.exec("ping " + input);
    element.innerHTML = input;
}
""")
    java_file = tmp_path / "Service.java"
    java_file.write_text("""
public class Service {
    public void execute(String userParam) {
        stmt.executeQuery("SELECT * FROM items WHERE code = '" + userParam + "'");
        Runtime.getRuntime().exec("sh -c " + userParam);
    }
}
""")

    findings = builtin_scan(tmp_path)
    files_flagged = {f.file.replace("\\", "/") for f in findings}
    assert "server.js" in files_flagged
    assert "Service.java" in files_flagged

def test_finding_deduplication():
    f1 = Finding(
        finding_id="find1",
        title="SQL injection found by Semgrep",
        description="Semgrep rule match",
        severity="critical",
        confidence=0.85,
        cwe="CWE-89",
        category="Injection",
        file="app/db.py",
        start_line=10,
        end_line=12,
        evidence=[Evidence(file="app/db.py", start_line=10, end_line=12, excerpt="db.query()", source="semgrep")],
        remediation="Use params",
        source="semgrep:sql-injection",
        status="needs_review",
        stable_fingerprint="fp-db-sql-10"
    )
    f2 = Finding(
        finding_id="find2",
        title="SQL injection found by Builtin",
        description="Built-in rule match",
        severity="high",
        confidence=0.72,
        cwe="CWE-89",
        category="Injection",
        file="app/db.py",
        start_line=11,
        end_line=11,
        evidence=[Evidence(file="app/db.py", start_line=11, end_line=11, excerpt="db.query(f'...'", source="builtin")],
        remediation="Use params",
        source="builtin:PY-SQL-FSTRING",
        status="needs_review",
        stable_fingerprint="fp-db-sql-10"
    )

    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    merged = deduped[0]
    assert merged.severity == "critical" # Picked highest severity
    assert merged.confidence == 0.85     # Picked highest confidence
    assert "semgrep" in merged.source and "builtin" in merged.source
    assert len(merged.evidence) == 2     # Both evidences preserved

def test_context_retrieval_ast_scope(tmp_path):
    code = """
import os

class UserManager:
    def authenticate(self, username, password):
        # Line 7
        token = "secret"
        cursor.execute(f"SELECT * FROM users WHERE user='{username}'")
        return token
"""
    p = tmp_path / "auth.py"
    p.write_text(code)

    dummy_finding = Finding(
        finding_id="auth_find",
        title="SQL Injection",
        description="f-string sql",
        severity="high",
        confidence=0.7,
        cwe="CWE-89",
        category="Injection",
        file="auth.py",
        start_line=8,
        end_line=8,
        evidence=[],
        remediation="Parametrize",
        source="builtin"
    )

    context = retrieve_context(tmp_path, dummy_finding)
    assert len(context) > 0
    scope_bundle = next((c for c in context if c.get("context_type") == "enclosing_scope"), None)
    assert scope_bundle is not None
    assert scope_bundle["retrieval_method"] == "ast"
    assert "authenticate" in scope_bundle["relevance"]

def test_safe_zip_metadata_and_hash(tmp_path):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("test.py", "print('hello world')")
    data = b.getvalue()
    
    count, total_bytes, chash = safe_extract_zip_with_metadata(data, tmp_path / "extracted")
    assert count == 1
    assert total_bytes > 0
    assert len(chash) == 64
    assert (tmp_path / "extracted" / "test.py").exists()

