"""
Tests for scan endpoints: list, get, delete, start scan, scan compare.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import SERVICE_HEADERS, make_scan, make_finding
from sentinelai.core.database import ScanType, ScanStatus, Severity


class TestListScans:
    async def test_list_scans_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/scans", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scans"] == []
        assert data["count"] == 0

    async def test_list_scans_returns_all(self, client: AsyncClient, auth_headers: dict):
        await make_scan("host1.example.com")
        await make_scan("host2.example.com")
        resp = await client.get("/api/v1/scans", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    async def test_list_scans_filter_by_status(self, client: AsyncClient, auth_headers: dict):
        await make_scan(status=ScanStatus.COMPLETED)
        await make_scan(status=ScanStatus.FAILED)
        resp = await client.get("/api/v1/scans?status=completed", headers=auth_headers)
        assert resp.json()["count"] == 1

    async def test_list_scans_filter_by_type(self, client: AsyncClient, auth_headers: dict):
        await make_scan(scan_type=ScanType.RECON)
        await make_scan(scan_type=ScanType.VULN)
        resp = await client.get("/api/v1/scans?scan_type=recon", headers=auth_headers)
        assert resp.json()["count"] == 1

    async def test_list_scans_pagination(self, client: AsyncClient, auth_headers: dict):
        for i in range(5):
            await make_scan(f"host{i}.com")
        resp = await client.get("/api/v1/scans?limit=2&offset=0", headers=auth_headers)
        assert resp.json()["count"] == 2

    async def test_list_scans_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/scans")
        assert resp.status_code == 401

    async def test_list_scans_with_service_key(self, client: AsyncClient):
        resp = await client.get("/api/v1/scans", headers=SERVICE_HEADERS)
        assert resp.status_code == 200


class TestGetScan:
    async def test_get_scan_success(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan("target.com", finding_count=3)
        resp = await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == scan_id
        assert data["target"] == "target.com"
        assert data["finding_count"] == 3
        assert "findings" in data

    async def test_get_scan_with_findings(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "SQL Injection", Severity.CRITICAL)
        await make_finding(scan_id, "XSS", Severity.HIGH)

        resp = await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert resp.status_code == 200
        findings = resp.json()["findings"]
        assert len(findings) == 2
        titles = {f["title"] for f in findings}
        assert "SQL Injection" in titles
        assert "XSS" in titles

    async def test_get_scan_not_found(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/scans/nonexistent-scan-id", headers=auth_headers)
        assert resp.status_code == 404

    async def test_get_scan_requires_auth(self, client: AsyncClient):
        scan_id = await make_scan()
        resp = await client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 401


class TestDeleteScan:
    async def test_delete_scan(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        resp = await client.delete(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert resp.status_code == 200

        get_resp = await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert get_resp.status_code == 404

    async def test_delete_nonexistent_scan(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/scans/no-such-scan", headers=auth_headers)
        assert resp.status_code == 404

    async def test_delete_scan_requires_auth(self, client: AsyncClient):
        scan_id = await make_scan()
        resp = await client.delete(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 401


class TestStartScan:
    async def test_start_recon_scan(self, client: AsyncClient):
        resp = await client.post("/api/v1/scan/recon", json={
            "target": "127.0.0.1",
            "authorization": {"confirm": True, "authorized_by": "test-tester"},
        }, headers=SERVICE_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert data["scan_type"] == "recon"
        assert "scan_id" in data

    async def test_start_vuln_scan(self, client: AsyncClient):
        resp = await client.post("/api/v1/scan/vuln", json={
            "target": "127.0.0.1",
            "open_ports": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
            "authorization": {"confirm": True, "authorized_by": "tester"},
        }, headers=SERVICE_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["scan_type"] == "vuln"

    async def test_start_full_scan(self, client: AsyncClient):
        resp = await client.post("/api/v1/scan/full", json={
            "target": "127.0.0.1",
            "authorization": {"confirm": True, "authorized_by": "tester"},
        }, headers=SERVICE_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["scan_type"] == "full"

    async def test_scan_requires_authorization_confirm(self, client: AsyncClient):
        resp = await client.post("/api/v1/scan/recon", json={
            "target": "example.com",
            "authorization": {"confirm": False, "authorized_by": "tester"},
        }, headers=SERVICE_HEADERS)
        assert resp.status_code == 403

    async def test_scan_rejects_invalid_target(self, client: AsyncClient):
        resp = await client.post("/api/v1/scan/recon", json={
            "target": "http://example.com/../../etc/passwd",
            "authorization": {"confirm": True, "authorized_by": "tester"},
        }, headers=SERVICE_HEADERS)
        assert resp.status_code in (400, 422)

    async def test_scan_requires_service_key(self, client: AsyncClient):
        resp = await client.post("/api/v1/scan/recon", json={
            "target": "127.0.0.1",
            "authorization": {"confirm": True, "authorized_by": "tester"},
        })
        assert resp.status_code == 401


class TestScanCompare:
    async def test_compare_two_scans(self, client: AsyncClient, auth_headers: dict):
        scan_a = await make_scan("compare.example.com", finding_count=2)
        scan_b = await make_scan("compare.example.com", finding_count=1)
        await make_finding(scan_a, "Old Finding", Severity.HIGH)
        await make_finding(scan_a, "Shared Finding", Severity.MEDIUM)
        await make_finding(scan_b, "Shared Finding", Severity.MEDIUM)
        await make_finding(scan_b, "New Finding", Severity.CRITICAL)

        resp = await client.get(
            f"/api/v1/scan-compare?a={scan_a}&b={scan_b}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_a"]["id"] == scan_a
        assert data["scan_b"]["id"] == scan_b
        assert "delta" in data
        assert "narrative" in data

        delta = data["delta"]
        new_titles = {f["title"] for f in delta["new"]}
        resolved_titles = {f["title"] for f in delta["resolved"]}
        assert "New Finding" in new_titles
        assert "Old Finding" in resolved_titles
        assert delta["persisted_count"] == 1

    async def test_compare_missing_scan_id(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        resp = await client.get(
            f"/api/v1/scan-compare?a={scan_id}&b=nonexistent-id",
            headers=auth_headers,
        )
        assert resp.status_code == 404

    async def test_compare_requires_auth(self, client: AsyncClient):
        scan_a = await make_scan()
        scan_b = await make_scan()
        resp = await client.get(f"/api/v1/scan-compare?a={scan_a}&b={scan_b}")
        assert resp.status_code == 401

    async def test_compare_identical_scans(self, client: AsyncClient, auth_headers: dict):
        scan_a = await make_scan("same.com")
        scan_b = await make_scan("same.com")
        await make_finding(scan_a, "Persistent Issue", Severity.HIGH)
        await make_finding(scan_b, "Persistent Issue", Severity.HIGH)

        resp = await client.get(
            f"/api/v1/scan-compare?a={scan_a}&b={scan_b}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        delta = resp.json()["delta"]
        assert delta["new"] == []
        assert delta["resolved"] == []
        assert delta["persisted_count"] == 1

    async def test_compare_detects_severity_change(self, client: AsyncClient, auth_headers: dict):
        scan_a = await make_scan("escalate.com")
        scan_b = await make_scan("escalate.com")
        await make_finding(scan_a, "Escalating Issue", Severity.LOW)
        await make_finding(scan_b, "Escalating Issue", Severity.CRITICAL)

        resp = await client.get(
            f"/api/v1/scan-compare?a={scan_a}&b={scan_b}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        changed = resp.json()["delta"]["changed_severity"]
        assert len(changed) == 1
        assert changed[0]["old_severity"] == "low"
        assert changed[0]["new_severity"] == "critical"
