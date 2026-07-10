"""
Tests for portfolio view, dashboard stats, MITRE heatmap, and KEV status.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import SERVICE_HEADERS, make_scan, make_finding
from sentinelai.core.database import ScanType, ScanStatus, Severity


class TestPortfolio:
    async def test_portfolio_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["targets"] == []
        assert data["total_targets"] == 0
        assert data["kev_total"] == 0

    async def test_portfolio_shows_completed_scans_only(self, client: AsyncClient, auth_headers: dict):
        await make_scan("completed.com", status=ScanStatus.COMPLETED)
        await make_scan("running.com", status=ScanStatus.RUNNING)
        await make_scan("failed.com", status=ScanStatus.FAILED)

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        data = resp.json()
        assert data["total_targets"] == 1
        assert data["targets"][0]["target"] == "completed.com"

    async def test_portfolio_deduplicates_by_target(self, client: AsyncClient, auth_headers: dict):
        await make_scan("web.example.com")
        await make_scan("web.example.com")
        await make_scan("db.example.com")

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        data = resp.json()
        assert data["total_targets"] == 2

    async def test_portfolio_computes_risk_score(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan("risky.com")
        await make_finding(scan_id, "Critical Bug", Severity.CRITICAL)
        await make_finding(scan_id, "High Bug", Severity.HIGH)

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        target = resp.json()["targets"][0]
        # Risk: 100 - 25(critical) - 10(high) = 65
        assert target["risk_score"] == 65

    async def test_portfolio_risk_score_floored_at_zero(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan("max-risk.com")
        for i in range(10):
            await make_finding(scan_id, f"Critical {i}", Severity.CRITICAL)

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        target = resp.json()["targets"][0]
        assert target["risk_score"] == 0

    async def test_portfolio_counts_kev_findings(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan("kev-target.com")
        await make_finding(scan_id, "KEV1", Severity.CRITICAL, is_kev=True)
        await make_finding(scan_id, "KEV2", Severity.HIGH, is_kev=True)
        await make_finding(scan_id, "Normal", Severity.MEDIUM, is_kev=False)

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        data = resp.json()
        assert data["kev_total"] == 2
        assert data["targets"][0]["kev_count"] == 2

    async def test_portfolio_excludes_fixed_findings_from_risk(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan("clean.com")
        await make_finding(scan_id, "Fixed Bug", Severity.CRITICAL, rem_status="fixed")
        await make_finding(scan_id, "Open Bug", Severity.LOW, rem_status="open")

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        target = resp.json()["targets"][0]
        # Only the LOW open finding counts: 100 - 1 = 99
        assert target["risk_score"] == 99

    async def test_portfolio_uses_latest_scan_per_target(self, client: AsyncClient, auth_headers: dict):
        # Two scans for the same target; portfolio should use the latest
        scan_old = await make_scan("host.com", finding_count=5)
        scan_new = await make_scan("host.com", finding_count=1)

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        data = resp.json()
        assert data["total_targets"] == 1
        assert data["targets"][0]["last_scan_id"] == scan_new

    async def test_portfolio_reports_critical_targets(self, client: AsyncClient, auth_headers: dict):
        scan = await make_scan("danger.com")
        await make_finding(scan, "Critical", Severity.CRITICAL)

        resp = await client.get("/api/v1/portfolio", headers=auth_headers)
        assert resp.json()["critical_targets"] == 1

    async def test_portfolio_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/portfolio")
        assert resp.status_code == 401

    async def test_portfolio_with_service_key(self, client: AsyncClient):
        resp = await client.get("/api/v1/portfolio", headers=SERVICE_HEADERS)
        assert resp.status_code == 200


class TestDashboardStats:
    async def test_stats_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] == 0
        assert data["total_findings"] == 0

    async def test_stats_counts_scans(self, client: AsyncClient, auth_headers: dict):
        await make_scan(status=ScanStatus.COMPLETED, finding_count=3, critical_count=1)
        await make_scan(status=ScanStatus.FAILED)
        await make_scan(status=ScanStatus.RUNNING)

        resp = await client.get("/api/v1/stats", headers=auth_headers)
        data = resp.json()
        assert data["total_scans"] == 3
        assert data["completed_scans"] == 1
        assert data["failed_scans"] == 1
        assert data["running_scans"] == 1
        assert data["total_findings"] == 3
        assert data["critical_findings"] == 1

    async def test_stats_includes_recent_scans(self, client: AsyncClient, auth_headers: dict):
        for i in range(7):
            await make_scan(f"host{i}.com")
        resp = await client.get("/api/v1/stats", headers=auth_headers)
        assert len(resp.json()["recent_scans"]) <= 5

    async def test_stats_breakdown_by_type(self, client: AsyncClient, auth_headers: dict):
        await make_scan(scan_type=ScanType.RECON)
        await make_scan(scan_type=ScanType.VULN)
        await make_scan(scan_type=ScanType.RECON)

        resp = await client.get("/api/v1/stats", headers=auth_headers)
        by_type = resp.json()["scans_by_type"]
        assert by_type.get("recon") == 2
        assert by_type.get("vuln") == 1

    async def test_stats_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/stats")
        assert resp.status_code == 401


class TestMitreHeatmap:
    async def test_heatmap_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/mitre/heatmap", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["unique_techniques"] == 0
        assert data["techniques"] == []

    async def test_heatmap_with_findings(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "Network Scan", Severity.HIGH, mitre_attack="T1046")
        await make_finding(scan_id, "Port Scan", Severity.MEDIUM, mitre_attack="T1046")
        await make_finding(scan_id, "Brute Force", Severity.CRITICAL, mitre_attack="T1110")

        resp = await client.get("/api/v1/mitre/heatmap", headers=auth_headers)
        data = resp.json()
        assert data["unique_techniques"] == 2
        assert data["total_findings_with_ttp"] == 3

        techniques_by_id = {t["id"]: t for t in data["techniques"]}
        assert techniques_by_id["T1046"]["count"] == 2
        assert techniques_by_id["T1110"]["count"] == 1
        assert techniques_by_id["T1046"]["name"] == "Network Service Discovery"

    async def test_heatmap_ignores_findings_without_ttp(self, client: AsyncClient, auth_headers: dict):
        scan_id = await make_scan()
        await make_finding(scan_id, "No TTP", Severity.HIGH, mitre_attack=None)
        await make_finding(scan_id, "Has TTP", Severity.HIGH, mitre_attack="T1595")

        resp = await client.get("/api/v1/mitre/heatmap", headers=auth_headers)
        data = resp.json()
        assert data["unique_techniques"] == 1
        assert data["total_findings_with_ttp"] == 1

    async def test_heatmap_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/mitre/heatmap")
        assert resp.status_code == 401


class TestKevStatus:
    async def test_kev_status_endpoint(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/kev/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "catalog_size" in data
        assert "fetch_url" in data
        assert "last_fetched" in data

    async def test_kev_status_with_service_key(self, client: AsyncClient):
        resp = await client.get("/api/v1/kev/status", headers=SERVICE_HEADERS)
        assert resp.status_code == 200

    async def test_kev_status_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/kev/status")
        assert resp.status_code == 401
