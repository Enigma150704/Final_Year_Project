import io
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app, db
from app.orchestrator import execute_scan_pipeline

client = TestClient(app)

def create_sample_zip():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("app/server.py", """
import subprocess
def query_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    subprocess.run("ls", shell=True)
""")
        z.writestr("requirements.txt", "fastapi\npsycopg2-binary\n")
    return b.getvalue()

def test_health_check():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "timestamp" in data

def test_project_creation_and_authorization_enforcement():
    # Attempt without authorization acknowledgement must fail
    resp = client.post("/api/projects", json={
        "name": "Unauthorized Project",
        "authorization_acknowledged": False
    })
    assert resp.status_code == 400

    # Creation with authorization succeeds
    resp = client.post("/api/projects", json={
        "name": "Authorized Test Repo",
        "description": "Integration test repository",
        "authorization_acknowledged": True
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Authorized Test Repo"
    assert data["authorization_acknowledged"] is True
    assert "id" in data

    # Verify project listing
    list_resp = client.get("/api/projects")
    assert list_resp.status_code == 200
    projects = list_resp.json()
    assert any(p["id"] == data["id"] for p in projects)

def test_full_scan_lifecycle_and_reviewer_workflow():
    # 1. Create Project
    p_resp = client.post("/api/projects", json={
        "name": "Lifecycle Test Project",
        "description": "E2E scan lifecycle test",
        "authorization_acknowledged": True
    })
    project_id = p_resp.json()["id"]

    # 2. Upload Repository
    zip_bytes = create_sample_zip()
    upload_resp = client.post(
        f"/api/projects/{project_id}/repositories",
        files={"file": ("repo.zip", zip_bytes, "application/zip")},
        data={"authorization_acknowledged": "true"}
    )
    assert upload_resp.status_code == 200
    snapshot = upload_resp.json()
    assert snapshot["original_filename"] == "repo.zip"
    assert len(snapshot["content_hash"]) == 64

    # 3. Start Scan
    scan_resp = client.post(
        f"/api/projects/{project_id}/scans",
        json={"snapshot_id": snapshot["id"], "configuration": {"enable_ai": True}}
    )
    assert scan_resp.status_code == 202
    scan_id = scan_resp.json()["id"]

    # Execute pipeline synchronously for test assertion
    execute_scan_pipeline(scan_id, db)

    # 4. Check Scan Status
    status_resp = client.get(f"/api/scans/{scan_id}")
    assert status_resp.status_code == 200
    scan_data = status_resp.json()
    assert scan_data["status"] == "completed"
    assert scan_data["progress"] == 100

    # 5. Check Profile
    profile_resp = client.get(f"/api/scans/{scan_id}/profile")
    assert profile_resp.status_code == 200
    profile = profile_resp.json()
    assert "Python" in profile["languages"]
    assert "FastAPI" in profile["frameworks"]

    # 6. Check Findings & Filtering
    findings_resp = client.get(f"/api/scans/{scan_id}/findings?severity=high")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) > 0
    first_finding = findings[0]
    assert first_finding["severity"] == "high"
    assert len(first_finding["evidence"]) > 0

    # 7. Check Finding Details
    fid = first_finding["id"]
    detail_resp = client.get(f"/api/findings/{fid}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == fid
    assert len(detail["context_bundles"]) > 0

    # 8. Reviewer Status Update (PATCH)
    patch_resp = client.patch(f"/api/findings/{fid}", json={
        "lifecycle_status": "confirmed",
        "comment": "Confirmed in code review as dynamic SQL execution.",
        "actor": "security-lead"
    })
    assert patch_resp.status_code == 200
    updated_finding = patch_resp.json()
    assert updated_finding["lifecycle_status"] == "confirmed"

    # 9. Verify Tools Run
    tools_resp = client.get(f"/api/scans/{scan_id}/tools")
    assert tools_resp.status_code == 200
    tools = tools_resp.json()
    assert any(t["analyzer_name"] == "builtin-rule-engine" for t in tools)

    # 10. Verify Full Report
    report_resp = client.get(f"/api/scans/{scan_id}/report")
    assert report_resp.status_code == 200
    report = report_resp.json()
    assert report["title"] == "AI Vulnerability Discovery Report"
    assert "limitations" in report
    assert report["summary"]["total"] >= 1

def test_legacy_analyze_compatibility():
    zip_bytes = create_sample_zip()
    resp = client.post(
        "/api/analyze",
        files={"file": ("test.zip", zip_bytes, "application/zip")},
        data={"project_name": "Legacy Test", "authorization_acknowledged": "true"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "project_id" in data
    assert "findings" in data
    assert "summary" in data
    assert "scanner_mode" in data
    assert len(data["findings"]) > 0

