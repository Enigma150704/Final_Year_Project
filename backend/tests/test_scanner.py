from pathlib import Path
from app.scanner import builtin_scan

def test_detects_dynamic_sql(tmp_path):
    p = tmp_path / "app.py"
    p.write_text('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")')
    findings = builtin_scan(tmp_path)
    assert any(f.cwe == "CWE-89" for f in findings)
