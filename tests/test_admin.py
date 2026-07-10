"""
Tests for admin-only endpoints: users list, activity, toggle user, analytics.
All admin endpoints require a JWT with admin=True.
The first registered user is always admin.
"""
import asyncio
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import register_user


class TestAdminUsers:
    async def test_list_users(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/users", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "users" in data
        assert data["count"] >= 1

    async def test_list_users_non_admin_rejected(self, client: AsyncClient, second_auth_headers: dict):
        resp = await client.get("/api/v1/admin/users", headers=second_auth_headers)
        assert resp.status_code == 403

    async def test_list_users_no_auth_rejected(self, client: AsyncClient):
        resp = await client.get("/api/v1/admin/users")
        assert resp.status_code == 401

    async def test_list_users_includes_all_users(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        resp = await client.get("/api/v1/admin/users", headers=auth_headers)
        assert resp.json()["count"] == 2

    async def test_list_users_includes_key_count(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/users", headers=auth_headers)
        user = resp.json()["users"][0]
        assert "active_keys" in user
        assert "total_requests" in user


class TestAdminUserActivity:
    async def test_admin_can_view_user_activity(self, client: AsyncClient, auth_headers: dict):
        # Get the current user's ID first
        me_resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        user_id = me_resp.json()["id"]

        resp = await client.get(f"/api/v1/admin/users/{user_id}/activity", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "user" in data
        assert "events" in data
        assert "service_usage" in data

    async def test_admin_activity_nonexistent_user(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/users/no-such-user/activity", headers=auth_headers)
        assert resp.status_code == 404

    async def test_non_admin_cannot_view_activity(self, client: AsyncClient, second_auth_headers: dict, auth_headers: dict):
        me_resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        user_id = me_resp.json()["id"]
        resp = await client.get(f"/api/v1/admin/users/{user_id}/activity", headers=second_auth_headers)
        assert resp.status_code == 403


class TestAdminUsage:
    async def test_admin_usage_logs(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/usage", headers=auth_headers)
        assert resp.status_code == 200
        assert "usage" in resp.json()

    async def test_non_admin_cannot_view_usage(self, client: AsyncClient, second_auth_headers: dict):
        resp = await client.get("/api/v1/admin/usage", headers=second_auth_headers)
        assert resp.status_code == 403


class TestAdminSecurityEvents:
    async def test_security_events_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/security-events", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data

    async def test_security_events_non_admin_rejected(self, client: AsyncClient, second_auth_headers: dict):
        resp = await client.get("/api/v1/admin/security-events", headers=second_auth_headers)
        assert resp.status_code == 403

    async def test_security_events_populated_after_failed_logins(self, client: AsyncClient, auth_headers: dict):
        # Register a user so we can attempt failed logins
        await register_user(client, "victim", "victim@example.com", "testpass123")
        for _ in range(3):
            await client.post("/api/v1/auth/login", json={
                "email": "victim@example.com",
                "password": "wrongpass",
            })
        # Yield to event loop so asyncio.create_task(_log_security_event) tasks can flush to DB
        await asyncio.sleep(0.05)
        resp = await client.get("/api/v1/admin/security-events", headers=auth_headers)
        events = resp.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "failed_login" in event_types


class TestAdminToggleUser:
    async def test_admin_deactivates_user(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        second_me = await client.get("/api/v1/auth/me", headers=second_auth_headers)
        second_user_id = second_me.json()["id"]

        resp = await client.patch(
            f"/api/v1/admin/users/{second_user_id}/toggle",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    async def test_admin_cannot_deactivate_self(self, client: AsyncClient, auth_headers: dict):
        me_resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        my_id = me_resp.json()["id"]

        resp = await client.patch(
            f"/api/v1/admin/users/{my_id}/toggle",
            headers=auth_headers,
        )
        assert resp.status_code == 400

    async def test_toggle_nonexistent_user(self, client: AsyncClient, auth_headers: dict):
        resp = await client.patch(
            "/api/v1/admin/users/no-such-user/toggle",
            headers=auth_headers,
        )
        assert resp.status_code == 404

    async def test_deactivated_user_cannot_login(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        second_me = await client.get("/api/v1/auth/me", headers=second_auth_headers)
        second_user_id = second_me.json()["id"]

        # Deactivate the user
        await client.patch(f"/api/v1/admin/users/{second_user_id}/toggle", headers=auth_headers)

        # Try to login as deactivated user
        login_resp = await client.post("/api/v1/auth/login", json={
            "email": "user2@example.com",
            "password": "password456",
        })
        assert login_resp.status_code == 403

    async def test_toggle_reactivates_user(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        second_me = await client.get("/api/v1/auth/me", headers=second_auth_headers)
        second_user_id = second_me.json()["id"]

        await client.patch(f"/api/v1/admin/users/{second_user_id}/toggle", headers=auth_headers)
        resp = await client.patch(f"/api/v1/admin/users/{second_user_id}/toggle", headers=auth_headers)
        assert resp.json()["is_active"] is True

    async def test_non_admin_cannot_toggle_user(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        me_resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        admin_id = me_resp.json()["id"]

        resp = await client.patch(
            f"/api/v1/admin/users/{admin_id}/toggle",
            headers=second_auth_headers,
        )
        assert resp.status_code == 403


class TestAdminAnalytics:
    async def test_admin_analytics_returns_data(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/analytics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "feature_usage" in data
        assert "top_users" in data
        assert "daily_activity" in data
        assert "security_events_by_type" in data

    async def test_analytics_non_admin_rejected(self, client: AsyncClient, second_auth_headers: dict):
        resp = await client.get("/api/v1/admin/analytics", headers=second_auth_headers)
        assert resp.status_code == 403

    async def test_analytics_custom_days(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/admin/analytics?days=30", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["period_days"] == 30
