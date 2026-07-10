"""
Tests for the remediation workflow: finding status updates, summary endpoint.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import SERVICE_HEADERS, make_scan, make_finding
from sentinelai.core.database import Severity


class TestUpdateFindingStatus:
    async def test_acknowledge_finding(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id, "SQL Injection", Severity.CRITICAL)

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "acknowledged"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "acknowledged"
        assert data["finding_id"] == finding_id

    async def test_mark_finding_in_progress(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id)

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "in_progress", "notes": "Working on a patch"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "in_progress"

    async def test_mark_finding_fixed(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id)

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "fixed", "notes": "Patched in v2.1"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "fixed"

    async def test_mark_finding_false_positive(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id)

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "false_positive"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    async def test_invalid_status_rejected(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id)

        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "not_a_valid_status"},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    async def test_update_nonexistent_finding(self, client: AsyncClient, auth_headers: dict):
        resp = await client.patch(
            "/api/v1/findings/no-such-finding/status",
            json={"status": "fixed"},
            headers=auth_headers,
        )
        assert resp.status_code == 404

    async def test_status_update_requires_auth(self, client: AsyncClient):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id)
        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "fixed"},
        )
        assert resp.status_code == 401

    async def test_status_update_with_service_key(self, client: AsyncClient):
        scan_id = await make_scan()
        finding_id = await make_finding(scan_id)
        resp = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "acknowledged"},
            headers=SERVICE_HEADERS,
        )
        assert resp.status_code == 200

    async def test_all_valid_statuses(self, client: AsyncClient, auth_headers: dict):
        for status in ("open", "acknowledged", "in_progress", "fixed", "false_positive"):
            scan_id = await make_scan()
            finding_id = await make_finding(scan_id)
            resp = await client.patch(
                f"/api/v1/findings/{finding_id}/status",
                json={"status": status},
                headers=auth_headers,
            )
            assert resp.status_code == 200, f"Status '{status}' failed: {resp.text}"


class TestRemediationSummary:
    async def test_summary_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/remediation/summary", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] == 0
        assert data["remediation_rate"] == 0
        assert data["kev_open"] == 0

    async def test_summary_counts_by_status(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "F1", Severity.CRITICAL, rem_status="open")
        await make_finding(scan_id, "F2", Severity.HIGH, rem_status="fixed")
        await make_finding(scan_id, "F3", Severity.MEDIUM, rem_status="acknowledged")
        await make_finding(scan_id, "F4", Severity.LOW, rem_status="in_progress")

        resp = await client.get("/api/v1/remediation/summary", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] == 4
        assert data["by_status"]["open"] == 1
        assert data["by_status"]["fixed"] == 1
        assert data["by_status"]["acknowledged"] == 1
        assert data["by_status"]["in_progress"] == 1

    async def test_remediation_rate_calculation(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "Fixed1", Severity.HIGH, rem_status="fixed")
        await make_finding(scan_id, "Fixed2", Severity.HIGH, rem_status="fixed")
        await make_finding(scan_id, "Open1", Severity.MEDIUM, rem_status="open")
        await make_finding(scan_id, "Open2", Severity.LOW, rem_status="open")

        resp = await client.get("/api/v1/remediation/summary", headers=auth_headers)
        data = resp.json()
        assert data["remediation_rate"] == 50.0

    async def test_summary_counts_kev_open(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "KEV Finding", Severity.CRITICAL,
                           cve_id="CVE-2021-44228", is_kev=True, rem_status="open")
        await make_finding(scan_id, "KEV Fixed", Severity.HIGH,
                           cve_id="CVE-2021-1234", is_kev=True, rem_status="fixed")
        await make_finding(scan_id, "Normal", Severity.MEDIUM, rem_status="open")

        resp = await client.get("/api/v1/remediation/summary", headers=auth_headers)
        data = resp.json()
        assert data["kev_open"] == 1

    async def test_summary_by_severity(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "C1", Severity.CRITICAL, rem_status="open")
        await make_finding(scan_id, "C2", Severity.CRITICAL, rem_status="fixed")
        await make_finding(scan_id, "H1", Severity.HIGH, rem_status="open")

        resp = await client.get("/api/v1/remediation/summary", headers=auth_headers)
        by_sev = resp.json()["by_severity"]
        assert by_sev["critical"]["total"] == 2
        assert by_sev["critical"]["fixed"] == 1
        assert by_sev["high"]["total"] == 1

    async def test_summary_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/remediation/summary")
        assert resp.status_code == 401

    async def test_summary_with_service_key(self, client: AsyncClient):
        resp = await client.get("/api/v1/remediation/summary", headers=SERVICE_HEADERS)
        assert resp.status_code == 200
