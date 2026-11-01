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


@pytest.mark.asyncio
async def test_edit_project_success(async_client: AsyncClient):
    """Users can update project name and target URL with valid inputs."""
    # Create project
    create_payload = {
        "name": "Original Project Name",
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }
    create_resp = await async_client.post("/api/projects", json=create_payload)
    assert create_resp.status_code == 201
    proj_id = create_resp.json()["id"]

    # Edit name and target_url
    patch_payload = {
        "name": "Updated Project Name",
        "target_url": "https://subdomain.example.com/app",
    }
    patch_resp = await async_client.patch(f"/api/projects/{proj_id}", json=patch_payload)
    assert patch_resp.status_code == 200
    updated_data = patch_resp.json()
    assert updated_data["name"] == "Updated Project Name"
    assert updated_data["target_url"] == "https://subdomain.example.com/app"

    # Verify persistence via GET
    get_resp = await async_client.get(f"/api/projects/{proj_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Updated Project Name"
    assert get_resp.json()["target_url"] == "https://subdomain.example.com/app"


@pytest.mark.asyncio
async def test_edit_project_url_validation_ssrf(async_client: AsyncClient):
    """Editing project URL must enforce security validation and SSRF protections."""
    # Create valid project
    create_payload = {
        "name": "SSRF Target Test",
        "target_url": "https://example.com",
        "authorization_confirmed": True,
    }
    create_resp = await async_client.post("/api/projects", json=create_payload)
    assert create_resp.status_code == 201
    proj_id = create_resp.json()["id"]

    # Blocked targets: loopback, link-local, file protocol, internal hostname
    prohibited_urls = [
        "http://127.0.0.1:8000",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://localhost:3000",
        "http://10.0.0.1",
    ]

    for bad_url in prohibited_urls:
        patch_resp = await async_client.patch(
            f"/api/projects/{proj_id}", json={"target_url": bad_url}
        )
        assert patch_resp.status_code == 400, f"Expected 400 for unsafe URL: {bad_url}"
        error_detail = patch_resp.json()["detail"]
        assert len(error_detail) > 0

    # Ensure original URL was preserved and not corrupted
    get_resp = await async_client.get(f"/api/projects/{proj_id}")
    assert get_resp.json()["target_url"] == "https://example.com/"


@pytest.mark.asyncio
async def test_edit_project_not_found(async_client: AsyncClient):
    """Editing non-existent project returns 404."""
    resp = await async_client.patch(
        "/api/projects/non-existent-id", json={"name": "New Name"}
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_project_with_cascade(async_client: AsyncClient):
    """Deleting a project removes the project and cascades deletion to scans and findings."""
    from app.database.session import AsyncSessionLocal
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.finding import Finding
    from sqlalchemy import select

    # 1. Create two projects to test isolation
    p1_resp = await async_client.post(
        "/api/projects",
        json={"name": "Project To Delete", "target_url": "https://delete-me.example.com", "authorization_confirmed": True},
    )
    p1_id = p1_resp.json()["id"]

    p2_resp = await async_client.post(
        "/api/projects",
        json={"name": "Project To Retain", "target_url": "https://keep-me.example.com", "authorization_confirmed": True},
    )
    p2_id = p2_resp.json()["id"]

    # 2. Mock scans on both projects to generate scans and findings
    mock_scan_p1 = {
        "success": True,
        "target_url": "https://delete-me.example.com/",
        "overall_score": 75,
        "score_grade": "Good",
        "findings": [
            {
                "source": "web",
                "category": "security_headers",
                "title": "Finding on P1",
                "description": "Desc P1",
                "severity": "medium",
                "confidence": 1.0,
                "risk_score": 55,
                "endpoint": "https://delete-me.example.com/",
                "status": "open",
            }
        ],
        "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "informational": 0},
        "error": None,
    }

    mock_scan_p2 = {
        "success": True,
        "target_url": "https://keep-me.example.com/",
        "overall_score": 80,
        "score_grade": "Good",
        "findings": [
            {
                "source": "web",
                "category": "security_headers",
                "title": "Finding on P2",
                "description": "Desc P2",
                "severity": "low",
                "confidence": 1.0,
                "risk_score": 35,
                "endpoint": "https://keep-me.example.com/",
                "status": "open",
            }
        ],
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 1, "informational": 0},
        "error": None,
    }

    import asyncio
    with patch("app.scanners.web.scanner.WebsiteScanner.scan", return_value=mock_scan_p1):
        s1_resp = await async_client.post(f"/api/projects/{p1_id}/scans")
        assert s1_resp.status_code == 202
        s1_id = s1_resp.json()["id"]
        await asyncio.sleep(0.1)

    with patch("app.scanners.web.scanner.WebsiteScanner.scan", return_value=mock_scan_p2):
        s2_resp = await async_client.post(f"/api/projects/{p2_id}/scans")
        assert s2_resp.status_code == 202
        s2_id = s2_resp.json()["id"]
        await asyncio.sleep(0.1)

    # Verify both have records in the database
    async with AsyncSessionLocal() as session:
        p1_findings = (await session.execute(select(Finding).where(Finding.scan_id == s1_id))).scalars().all()
        p2_findings = (await session.execute(select(Finding).where(Finding.scan_id == s2_id))).scalars().all()
        assert len(p1_findings) == 1
        assert len(p2_findings) == 1

    # 3. Delete Project 1
    del_resp = await async_client.delete(f"/api/projects/{p1_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # 4. Verify Project 1, its scan, and its findings are gone
    async with AsyncSessionLocal() as session:
        proj1 = (await session.execute(select(Project).where(Project.id == p1_id))).scalar_one_or_none()
        assert proj1 is None, "Project 1 must be deleted"

        scan1 = (await session.execute(select(Scan).where(Scan.id == s1_id))).scalar_one_or_none()
        assert scan1 is None, "Project 1 scan must be deleted via cascade"

        f1 = (await session.execute(select(Finding).where(Finding.scan_id == s1_id))).scalars().all()
        assert len(f1) == 0, "Project 1 findings must be deleted via cascade"

        # 5. Verify Project 2, its scan, and its findings are completely intact
        proj2 = (await session.execute(select(Project).where(Project.id == p2_id))).scalar_one_or_none()
        assert proj2 is not None, "Project 2 must remain unaffected"

        scan2 = (await session.execute(select(Scan).where(Scan.id == s2_id))).scalar_one_or_none()
        assert scan2 is not None, "Project 2 scan must remain unaffected"

        f2 = (await session.execute(select(Finding).where(Finding.scan_id == s2_id))).scalars().all()
        assert len(f2) == 1, "Project 2 findings must remain unaffected"


@pytest.mark.asyncio
async def test_delete_project_not_found(async_client: AsyncClient):
    """Deleting non-existent project returns 404."""
    resp = await async_client.delete("/api/projects/non-existent-proj-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_rescan_finding_status_persistence(async_client: AsyncClient):
    """During rescans, matching findings preserve Resolved, False Positive, and In Progress statuses;
    new findings start as Open; disappearing findings remain in previous scan history;
    and severity counters remain independent of workflow statuses."""
    import asyncio

    # 1. Create project
    proj_resp = await async_client.post(
        "/api/projects",
        json={"name": "Persistence Test Target", "target_url": "https://persist.example.com", "authorization_confirmed": True},
    )
    assert proj_resp.status_code == 201
    proj_id = proj_resp.json()["id"]

    # 2. First scan findings
    scan1_findings = [
        {
            "source": "web",
            "category": "security_headers",
            "title": "Missing Content-Security-Policy",
            "description": "CSP missing",
            "severity": "medium",
            "confidence": 1.0,
            "risk_score": 55,
            "cwe": "CWE-693",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
        {
            "source": "web",
            "category": "security_headers",
            "title": "Missing Clickjacking Protection",
            "description": "XFO missing",
            "severity": "medium",
            "confidence": 1.0,
            "risk_score": 55,
            "cwe": "CWE-1021",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
        {
            "source": "web",
            "category": "security_headers",
            "title": "Missing Referrer-Policy Header",
            "description": "Referrer policy missing",
            "severity": "low",
            "confidence": 1.0,
            "risk_score": 35,
            "cwe": "CWE-200",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
        {
            "source": "web",
            "category": "configuration",
            "title": "Public robots.txt Disclosing Sensitive Paths",
            "description": "Robots.txt discloses paths",
            "severity": "informational",
            "confidence": 1.0,
            "risk_score": 15,
            "cwe": "CWE-200",
            "endpoint": "https://persist.example.com/robots.txt",
            "status": "open",
        },
    ]

    mock_result_1 = {
        "success": True,
        "target_url": "https://persist.example.com/",
        "overall_score": 70,
        "score_grade": "Needs Improvement",
        "findings": scan1_findings,
        "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "informational": 1},
        "error": None,
    }

    with patch("app.scanners.web.scanner.WebsiteScanner.scan", return_value=mock_result_1):
        s1_trigger = await async_client.post(f"/api/projects/{proj_id}/scans")
        assert s1_trigger.status_code == 202
        scan1_id = s1_trigger.json()["id"]
        await asyncio.sleep(0.1)

    # 3. Retrieve Scan 1 findings and update their workflow statuses
    s1_get = await async_client.get(f"/api/scans/{scan1_id}/findings")
    assert s1_get.status_code == 200
    s1_persisted_findings = s1_get.json()
    assert len(s1_persisted_findings) == 4

    csp_finding = next(f for f in s1_persisted_findings if f["title"] == "Missing Content-Security-Policy")
    xfo_finding = next(f for f in s1_persisted_findings if f["title"] == "Missing Clickjacking Protection")
    ref_finding = next(f for f in s1_persisted_findings if f["title"] == "Missing Referrer-Policy Header")
    robots_finding = next(f for f in s1_persisted_findings if f["title"] == "Public robots.txt Disclosing Sensitive Paths")

    # Mark CSP as resolved
    await async_client.patch(f"/api/findings/{csp_finding['id']}", json={"status": "resolved"})
    # Mark XFO as false_positive
    await async_client.patch(f"/api/findings/{xfo_finding['id']}", json={"status": "false_positive"})
    # Mark Referrer-Policy as in_progress
    await async_client.patch(f"/api/findings/{ref_finding['id']}", json={"status": "in_progress"})
    # Leave robots.txt as open

    # 4. Trigger Scan 2 (Rescan)
    # In Scan 2:
    # - CSP is still detected -> should be preserved as "resolved"
    # - XFO is still detected -> should be preserved as "false_positive"
    # - Referrer-Policy is still detected -> should be preserved as "in_progress"
    # - robots.txt DISAPPEARED (fixed/absent in new scan) -> should remain in Scan 1 history
    # - New finding detected: "Server Banner Exposing Software Version" -> should start as "open"
    scan2_findings = [
        {
            "source": "web",
            "category": "security_headers",
            "title": "Missing Content-Security-Policy",
            "description": "CSP missing",
            "severity": "medium",
            "confidence": 1.0,
            "risk_score": 55,
            "cwe": "CWE-693",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
        {
            "source": "web",
            "category": "security_headers",
            "title": "Missing Clickjacking Protection",
            "description": "XFO missing",
            "severity": "medium",
            "confidence": 1.0,
            "risk_score": 55,
            "cwe": "CWE-1021",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
        {
            "source": "web",
            "category": "security_headers",
            "title": "Missing Referrer-Policy Header",
            "description": "Referrer policy missing",
            "severity": "low",
            "confidence": 1.0,
            "risk_score": 35,
            "cwe": "CWE-200",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
        {
            "source": "web",
            "category": "information_exposure",
            "title": "Server Banner Exposing Software Version",
            "description": "Apache 2.4 exposed",
            "severity": "low",
            "confidence": 0.95,
            "risk_score": 35,
            "cwe": "CWE-200",
            "endpoint": "https://persist.example.com/",
            "status": "open",
        },
    ]

    mock_result_2 = {
        "success": True,
        "target_url": "https://persist.example.com/",
        "overall_score": 65,
        "score_grade": "Needs Improvement",
        "findings": scan2_findings,
        "counts": {"critical": 0, "high": 0, "medium": 2, "low": 2, "informational": 0},
        "error": None,
    }

    with patch("app.scanners.web.scanner.WebsiteScanner.scan", return_value=mock_result_2):
        s2_trigger = await async_client.post(f"/api/projects/{proj_id}/scans")
        assert s2_trigger.status_code == 202
        scan2_id = s2_trigger.json()["id"]
        await asyncio.sleep(0.1)

    # 5. Verify Scan 2 findings and status persistence
    s2_get = await async_client.get(f"/api/scans/{scan2_id}/findings")
    assert s2_get.status_code == 200
    s2_persisted_findings = s2_get.json()
    assert len(s2_persisted_findings) == 4

    csp_s2 = next(f for f in s2_persisted_findings if f["title"] == "Missing Content-Security-Policy")
    xfo_s2 = next(f for f in s2_persisted_findings if f["title"] == "Missing Clickjacking Protection")
    ref_s2 = next(f for f in s2_persisted_findings if f["title"] == "Missing Referrer-Policy Header")
    server_s2 = next(f for f in s2_persisted_findings if f["title"] == "Server Banner Exposing Software Version")

    assert csp_s2["status"] == "resolved", "Resolved status must be preserved on rescan"
    assert xfo_s2["status"] == "false_positive", "False Positive status must be preserved on rescan"
    assert ref_s2["status"] == "in_progress", "In Progress status must be preserved on rescan"
    assert server_s2["status"] == "open", "New finding must start as open"

    # 6. Verify Scan 1 history is completely untouched
    s1_history_get = await async_client.get(f"/api/scans/{scan1_id}/findings")
    assert s1_history_get.status_code == 200
    s1_history_findings = s1_history_get.json()
    assert len(s1_history_findings) == 4
    # The disappeared robots.txt finding is still in Scan 1!
    assert any(f["title"] == "Public robots.txt Disclosing Sensitive Paths" for f in s1_history_findings)

    # 7. Verify severity counters on Scan 2 are independent of workflow statuses
    scan2_detail = await async_client.get(f"/api/scans/{scan2_id}")
    assert scan2_detail.status_code == 200
    s2_data = scan2_detail.json()
    assert s2_data["findings_count"] == 4
    assert s2_data["medium_count"] == 2
    assert s2_data["low_count"] == 2
    assert s2_data["critical_count"] == 0
    assert s2_data["overall_score"] == 65


def test_compute_finding_fingerprint_normalization():
    """Verify that fingerprinting is deterministic and normalizes trailing slashes, casing, and defaults."""
    from app.risk.fingerprint import compute_finding_fingerprint

    fp1 = compute_finding_fingerprint(
        target_url="https://example.com/",
        category="Security_Headers",
        check_rule_id="Missing Content-Security-Policy",
        affected_resource="https://example.com/",
    )
    fp2 = compute_finding_fingerprint(
        target_url="https://example.com",
        category="security_headers",
        check_rule_id="Missing Content-Security-Policy",
        affected_resource="https://example.com",
    )
    assert fp1 == fp2, "Fingerprints must match despite trailing slashes or category casing"

    # Default fallback for affected_resource
    fp3 = compute_finding_fingerprint(
        target_url="https://example.com",
        category="security_headers",
        check_rule_id="Missing Content-Security-Policy",
        affected_resource=None,
    )
    assert fp1 == fp3, "Affected resource must fallback to normalized target URL"

    # Different check rule produces different fingerprint
    fp4 = compute_finding_fingerprint(
        target_url="https://example.com",
        category="security_headers",
        check_rule_id="Missing Strict-Transport-Security (HSTS)",
        affected_resource="https://example.com",
    )
    assert fp1 != fp4, "Different rules must produce different fingerprints"



