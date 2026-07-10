"""
Tests for recurring scan schedules: create, list, toggle, delete.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import SERVICE_HEADERS


VALID_SCHEDULE = {
    "name": "Daily Web Scan",
    "target": "127.0.0.1",
    "scan_type": "recon",
    "interval_hours": 24,
    "authorized_by": "test-tester",
}


class TestCreateSchedule:
    async def test_create_schedule_success(self, client: AsyncClient):
        resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert "schedule" in data
        sched = data["schedule"]
        assert sched["name"] == "Daily Web Scan"
        assert sched["target"] == "127.0.0.1"
        assert sched["enabled"] is True
        assert sched["interval_hours"] == 24

    async def test_create_schedule_requires_api_key(self, client: AsyncClient):
        resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE)
        assert resp.status_code == 401

    async def test_create_schedule_invalid_scan_type(self, client: AsyncClient):
        invalid = {**VALID_SCHEDULE, "scan_type": "exploit"}
        resp = await client.post("/api/v1/schedules", json=invalid, headers=SERVICE_HEADERS)
        assert resp.status_code == 422

    async def test_create_schedule_interval_too_large(self, client: AsyncClient):
        invalid = {**VALID_SCHEDULE, "interval_hours": 9999}
        resp = await client.post("/api/v1/schedules", json=invalid, headers=SERVICE_HEADERS)
        assert resp.status_code == 422

    async def test_create_schedule_vuln_type(self, client: AsyncClient):
        schedule = {**VALID_SCHEDULE, "scan_type": "vuln", "name": "Vuln Check"}
        resp = await client.post("/api/v1/schedules", json=schedule, headers=SERVICE_HEADERS)
        assert resp.status_code == 200

    async def test_create_schedule_full_type(self, client: AsyncClient):
        schedule = {**VALID_SCHEDULE, "scan_type": "full", "name": "Full Audit"}
        resp = await client.post("/api/v1/schedules", json=schedule, headers=SERVICE_HEADERS)
        assert resp.status_code == 200


class TestListSchedules:
    async def test_list_schedules_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/schedules", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["schedules"] == []

    async def test_list_schedules_after_creation(self, client: AsyncClient, auth_headers: dict):
        await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        await client.post("/api/v1/schedules", json={**VALID_SCHEDULE, "name": "Weekly"}, headers=SERVICE_HEADERS)

        resp = await client.get("/api/v1/schedules", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    async def test_list_schedules_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/schedules")
        assert resp.status_code == 401

    async def test_list_schedules_with_service_key(self, client: AsyncClient):
        resp = await client.get("/api/v1/schedules", headers=SERVICE_HEADERS)
        assert resp.status_code == 200


class TestToggleSchedule:
    async def test_toggle_disables_schedule(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        sched_id = create_resp.json()["schedule"]["id"]

        resp = await client.patch(f"/api/v1/schedules/{sched_id}/toggle", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["schedule"]["enabled"] is False

    async def test_toggle_re_enables_schedule(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        sched_id = create_resp.json()["schedule"]["id"]

        await client.patch(f"/api/v1/schedules/{sched_id}/toggle", headers=auth_headers)
        resp = await client.patch(f"/api/v1/schedules/{sched_id}/toggle", headers=auth_headers)
        assert resp.json()["schedule"]["enabled"] is True

    async def test_toggle_nonexistent_schedule(self, client: AsyncClient, auth_headers: dict):
        resp = await client.patch("/api/v1/schedules/no-such-id/toggle", headers=auth_headers)
        assert resp.status_code == 404

    async def test_toggle_requires_auth(self, client: AsyncClient):
        create_resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        sched_id = create_resp.json()["schedule"]["id"]
        resp = await client.patch(f"/api/v1/schedules/{sched_id}/toggle")
        assert resp.status_code == 401


class TestDeleteSchedule:
    async def test_delete_schedule(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        sched_id = create_resp.json()["schedule"]["id"]

        del_resp = await client.delete(f"/api/v1/schedules/{sched_id}", headers=auth_headers)
        assert del_resp.status_code == 200

        list_resp = await client.get("/api/v1/schedules", headers=auth_headers)
        assert list_resp.json()["count"] == 0

    async def test_delete_nonexistent_schedule(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/schedules/no-such-id", headers=auth_headers)
        assert resp.status_code == 404

    async def test_delete_requires_auth(self, client: AsyncClient):
        create_resp = await client.post("/api/v1/schedules", json=VALID_SCHEDULE, headers=SERVICE_HEADERS)
        sched_id = create_resp.json()["schedule"]["id"]
        resp = await client.delete(f"/api/v1/schedules/{sched_id}")
        assert resp.status_code == 401
