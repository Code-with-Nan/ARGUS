import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import scans as scans_api
from app.core.config import settings
from app.core.database import Base, get_db
from app.dependencies.auth import get_current_user
from app.models import Finding, FindingDetails, Remediation, Scan, ScanMetadata, VerificationResult
from app.models.auth import User
from app.schemas.scans import SecurityReportResponse
from app.services.ai_explainer import explain_finding
from app.services import ai_explainer
from app.services.pdf_report import build_scan_pdf
from app.services.remediation import apply_unified_diff
from app.services.security_scanner import scan_project


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    app = FastAPI()
    app.include_router(scans_api.router)

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    db = session_factory()
    demo_user = User(
        id="test-user",
        email="scans@example.com",
        display_name="Scan Test User",
        password_hash="test-hash",
        is_active=True,
    )
    db.add(demo_user)
    db.commit()
    app.dependency_overrides[get_current_user] = lambda: demo_user
    monkeypatch.setattr(settings, "workspace_dir", str(tmp_path / "workspaces"))
    monkeypatch.setattr(settings, "api_token", None)
    with TestClient(app) as test_client:
        yield test_client
    db.close()
    engine.dispose()


def _zip_file(name: str, content: str) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return stream.getvalue()


def _fake_report(project_path, *, timeout, include_dependency_audits):
    file_path = project_path / "app.py"
    vulnerable = "eval(" in file_path.read_text(encoding="utf-8")
    findings = []
    if vulnerable:
        findings.append(
            {
                "title": "Use of eval detected",
                "severity": "HIGH",
                "confidence": "HIGH",
                "file": "app.py",
                "line": 1,
                "test_id": "B307",
                "code": "eval(input())",
                "scanner": "Bandit",
                "rule_id": "B307",
                "references": [],
                "metadata": {},
            }
        )
    return {
        "scanner": "Bandit",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings,
        "scanner_results": {
            "Bandit": {"status": "completed", "findings": len(findings), "error": None}
        },
    }


def test_scanner_reports_tool_coverage_and_sample_findings():
    result = scan_project("tests/sample_project", include_dependency_audits=False)
    assert result["status"] in {"completed", "partial"}
    assert result["total_findings"] >= 1
    assert result["scanner_results"]["Bandit"]["status"] == "completed"
    assert "Semgrep" in result["scanner_results"]


def test_zip_traversal_is_rejected(client):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../outside.py", "print('unsafe')")
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("unsafe.zip", stream.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "Unsafe archive path" in response.json()["detail"]


def test_upload_history_details_explanation_and_pdf(client, monkeypatch):
    monkeypatch.setattr(scans_api, "scan_project", _fake_report)
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("demo.zip", _zip_file("app.py", "eval(input())\n"), "application/zip")},
    )
    assert response.status_code == 201
    scan = response.json()
    assert scan["total_findings"] == 1
    finding = scan["findings"][0]

    history = client.get("/api/v1/scans?page=1&page_size=5")
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert "findings" not in history.json()["items"][0]

    details = client.get(f"/api/v1/scans/{scan['scan_id']}")
    assert details.status_code == 200
    assert details.json()["findings"][0]["id"] == finding["id"]

    explanation = client.post(
        f"/api/v1/scans/{scan['scan_id']}/findings/{finding['id']}/explanation"
    )
    assert explanation.status_code == 200
    assert explanation.json()["source"] == "deterministic_fallback"

    pdf = client.get(f"/api/v1/scans/{scan['scan_id']}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF-")


def test_remediation_requires_approval_and_followup_scan(client, monkeypatch):
    monkeypatch.setattr(scans_api, "scan_project", _fake_report)
    upload = client.post(
        "/api/v1/scans/upload",
        files={"file": ("demo.zip", _zip_file("app.py", "eval(input())\n"), "application/zip")},
    ).json()
    scan_id = upload["scan_id"]
    finding_id = upload["findings"][0]["id"]
    patch = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-eval(input())\n+print(input())\n"
    created = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/remediations",
        json={"patch": patch},
    )
    assert created.status_code == 200
    remediation_id = created.json()["id"]

    blocked = client.post(f"/api/v1/scans/remediations/{remediation_id}/apply")
    assert blocked.status_code == 409

    approved = client.post(
        f"/api/v1/scans/remediations/{remediation_id}/approve",
        json={"approved_by": "security-reviewer"},
    )
    assert approved.status_code == 200
    applied = client.post(f"/api/v1/scans/remediations/{remediation_id}/apply")
    assert applied.status_code == 200
    assert applied.json()["verification"]["status"] == "VERIFIED_FIXED"
    assert applied.json()["verification"]["target_finding_present"] is False
    assert applied.json()["followup_scan"]["scan_id"]


def test_real_bandit_followup_verifies_applied_fix(client):
    upload = client.post(
        "/api/v1/scans/upload",
        files={"file": ("real-bandit.zip", _zip_file("app.py", "value = eval(input())\n"), "application/zip")},
    )
    assert upload.status_code == 201
    initial = upload.json()
    bandit_findings = [item for item in initial["findings"] if item.get("scanner") == "Bandit"]
    assert bandit_findings
    assert initial["scanner_results"]["Bandit"]["status"] == "completed"
    finding = bandit_findings[0]
    patch = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = eval(input())\n+value = input()\n"
    created = client.post(
        f"/api/v1/scans/{initial['scan_id']}/findings/{finding['id']}/remediations",
        json={"patch": patch},
    )
    assert created.status_code == 200
    approved = client.post(
        f"/api/v1/scans/remediations/{created.json()['id']}/approve",
        json={"approved_by": "integration-test"},
    )
    assert approved.status_code == 200
    applied = client.post(f"/api/v1/scans/remediations/{created.json()['id']}/apply")
    assert applied.status_code == 200
    result = applied.json()
    assert result["followup_scan"]["scanner_results"]["Bandit"]["status"] == "completed"
    assert result["verification"]["status"] == "VERIFIED_FIXED"
    assert result["verification"]["target_finding_present"] is False


def test_failed_followup_scanner_is_inconclusive(client, monkeypatch):
    calls = 0

    def scanner(project_path, *, timeout, include_dependency_audits):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _fake_report(project_path, timeout=timeout, include_dependency_audits=include_dependency_audits)
        return {
            "scanner": "None",
            "status": "failed",
            "total_findings": 0,
            "findings": [],
            "scanner_results": {"Bandit": {"status": "failed", "findings": 0, "error": "timeout"}},
        }

    monkeypatch.setattr(scans_api, "scan_project", scanner)
    upload = client.post(
        "/api/v1/scans/upload",
        files={"file": ("demo.zip", _zip_file("app.py", "eval(input())\n"), "application/zip")},
    ).json()
    finding_id = upload["findings"][0]["id"]
    patch = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-eval(input())\n+print(input())\n"
    created = client.post(
        f"/api/v1/scans/{upload['scan_id']}/findings/{finding_id}/remediations",
        json={"patch": patch},
    ).json()
    client.post(
        f"/api/v1/scans/remediations/{created['id']}/approve",
        json={"approved_by": "integration-test"},
    )
    applied = client.post(f"/api/v1/scans/remediations/{created['id']}/apply")
    assert applied.status_code == 200
    assert applied.json()["verification"]["status"] == "VERIFICATION_FAILED"
    assert applied.json()["verification"]["target_finding_present"] is None


def test_api_token_protects_upload(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "local-test-token")
    monkeypatch.setattr(scans_api, "scan_project", _fake_report)
    archive = _zip_file("app.py", "print('safe')\n")
    unauthorized = client.post(
        "/api/v1/scans/upload",
        files={"file": ("demo.zip", archive, "application/zip")},
    )
    assert unauthorized.status_code == 401
    authorized = client.post(
        "/api/v1/scans/upload",
        files={"file": ("demo.zip", archive, "application/zip")},
        headers={"X-API-Key": "local-test-token"},
    )
    assert authorized.status_code == 201


def test_patch_rejects_context_mismatch(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("actual = 1\n", encoding="utf-8")
    bad_patch = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-expected = 1\n+changed = 1\n"
    with pytest.raises(ValueError, match="context"):
        apply_unified_diff(tmp_path, bad_patch)
    assert target.read_text(encoding="utf-8") == "actual = 1\n"


def test_fallback_is_explicitly_labelled():
    result = explain_finding({"title": "Unsafe operation", "severity": "HIGH"})
    assert result["source"] == "deterministic_fallback"
    assert "not an AI-generated response" in result["explanation"]


def test_configured_ai_provider_uses_https_without_code_by_default(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        def read(self, size):
            return json.dumps({"choices": [{"message": {"content": "Provider explanation"}}]}).encode()

    class FakeConnection:
        def __init__(self, host, port, timeout):
            captured["host"] = host

        def request(self, method, path, body, headers):
            captured["payload"] = json.loads(body)

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(ai_explainer.http.client, "HTTPSConnection", FakeConnection)
    config = SimpleNamespace(
        ai_provider="openai-compatible",
        ai_api_url="https://ai.example/v1/chat/completions",
        ai_api_key="test-token",
        ai_model="test-model",
        ai_timeout_seconds=2,
        ai_include_code=False,
    )
    result = explain_finding({"title": "Finding", "code": "sensitive source"}, config=config)
    assert result == {"explanation": "Provider explanation", "source": "openai-compatible"}
    assert "sensitive source" not in json.dumps(captured["payload"])

    config.ai_api_url = "file:///etc/passwd"
    assert explain_finding({"title": "Finding"}, config=config)["source"] == "deterministic_fallback"