from unittest.mock import patch
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_project_authorization_required(async_client: AsyncClient):
    """Creating a project without explicit authorization confirmation must be rejected."""
    payload = {
        "name": "Unauthorized Target",
        "target_url": "https://example.com",
        "authorization_confirmed": False,
    }
    response = await async_client.post("/api/projects", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_project_invalid_url(async_client: AsyncClient):
    """Creating a project with a prohibited protocol or invalid URL must be rejected."""
    payload = {
        "name": "Invalid Target",
        "target_url": "file:///etc/passwd",
        "authorization_confirmed": True,
    }
    response = await async_client.post("/api/projects", json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_project_lifecycle_and_scan_e2e(async_client: AsyncClient):
    """Complete end-to-end verification: Project creation -> Scan trigger -> Finding retrieval -> Status update."""
    # 1. Create legitimate authorized project
    create_payload = {
        "name": "E2E Assessment Target",
        "target_url": "https://example.org",
        "authorization_confirmed": True,
    }
    proj_resp = await async_client.post("/api/projects", json=create_payload)
    assert proj_resp.status_code == 201
    project_data = proj_resp.json()
    project_id = project_data["id"]
    assert project_data["name"] == "E2E Assessment Target"
    assert project_data["authorization_confirmed"] is True

    # 2. List projects
    list_resp = await async_client.get("/api/projects")
    assert list_resp.status_code == 200
    projects = list_resp.json()
    assert any(p["id"] == project_id for p in projects)

    # 3. Mock scanner execution to produce deterministic findings
    mock_scan_result = {
        "success": True,
        "target_url": "https://example.org/",
        "overall_score": 68,
        "score_grade": "Needs Improvement",
        "findings": [
            {
                "source": "web",
                "category": "security_headers",
                "title": "Missing Content-Security-Policy",
                "description": "CSP is missing.",
                "severity": "medium",
                "confidence": 1.0,
                "risk_score": 55,
                "cwe": "CWE-693",
                "endpoint": "https://example.org/",
                "evidence": "Header not found.",
                "remediation": "Add CSP.",
                "status": "open",
            },
            {
                "source": "web",
                "category": "security_headers",
                "title": "Missing Clickjacking Protection",
                "description": "X-Frame-Options is missing.",
                "severity": "medium",
                "confidence": 1.0,
                "risk_score": 55,
                "cwe": "CWE-1021",
                "endpoint": "https://example.org/",
                "evidence": "Header not found.",
                "remediation": "Add X-Frame-Options.",
                "status": "open",
            },
        ],
        "counts": {"critical": 0, "high": 0, "medium": 2, "low": 0, "informational": 0},
        "error": None,
    }

    with patch("app.scanners.web.scanner.WebsiteScanner.scan", return_value=mock_scan_result):
        # 4. Trigger Scan
        scan_resp = await async_client.post(f"/api/projects/{project_id}/scans")
        assert scan_resp.status_code == 202
        scan_data = scan_resp.json()
        scan_id = scan_data["id"]
        assert scan_data["project_id"] == project_id

        # Allow background task execution
        import asyncio
        await asyncio.sleep(0.1)

        # 5. Retrieve Scan Detail
        scan_detail_resp = await async_client.get(f"/api/scans/{scan_id}")
        assert scan_detail_resp.status_code == 200
        detail = scan_detail_resp.json()
        assert detail["status"] == "completed"
        assert detail["overall_score"] == 68
        assert detail["score_grade"] == "Needs Improvement"
        assert detail["medium_count"] == 2
        assert len(detail["findings"]) == 2

        # 6. Retrieve Findings
        findings_resp = await async_client.get(f"/api/scans/{scan_id}/findings")
        assert findings_resp.status_code == 200
        findings = findings_resp.json()
        assert len(findings) == 2
        finding_id = findings[0]["id"]
        assert findings[0]["status"] == "open"

        # 7. Update Finding Status via PATCH
        patch_resp = await async_client.patch(
            f"/api/findings/{finding_id}", json={"status": "resolved"}
        )
        assert patch_resp.status_code == 200
        updated_finding = patch_resp.json()
        assert updated_finding["status"] == "resolved"

        # 8. Retrieve Scan Summary
        summary_resp = await async_client.get(f"/api/scans/{scan_id}/summary")
        assert summary_resp.status_code == 200
        summary = summary_resp.json()
        assert summary["overall_score"] == 68
        assert summary["severity_breakdown"]["medium"] == 2
        assert len(summary["top_risks"]) == 2

        # 9. Verify finding status persistence across refetch (simulating page refresh)
        refetch_resp = await async_client.get(f"/api/scans/{scan_id}/findings")
        assert refetch_resp.status_code == 200
        refetched_findings = refetch_resp.json()
        persisted_finding = next(f for f in refetched_findings if f["id"] == finding_id)
        assert persisted_finding["status"] == "resolved", "Finding status must persist in database on refetch"


@pytest.mark.asyncio
async def test_invalid_scan_id_returns_404(async_client: AsyncClient):
    """Accessing an invalid or non-existent scan ID must return 404 with descriptive detail."""
    invalid_id = "non-existent-scan-999"
    resp = await async_client.get(f"/api/scans/{invalid_id}")
    assert resp.status_code == 404
    data = resp.json()
    assert f"Scan with ID '{invalid_id}' does not exist." in data["detail"]


@pytest.mark.asyncio
async def test_invalid_project_id_returns_404(async_client: AsyncClient):
    """Accessing an invalid or non-existent project ID must return 404 with descriptive detail."""
    invalid_id = "non-existent-proj-999"
    resp = await async_client.get(f"/api/projects/{invalid_id}")
    assert resp.status_code == 404
    data = resp.json()
    assert f"Project with ID '{invalid_id}' does not exist." in data["detail"]

