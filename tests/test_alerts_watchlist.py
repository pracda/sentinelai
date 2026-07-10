"""
Tests for alert rules and CVE/service watchlist.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import register_user


VALID_RULE = {
    "name": "Critical Alert",
    "trigger": "critical_finding",
    "notify_email": "security@example.com",
}


class TestAlertRules:
    async def test_create_alert_rule(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post("/api/v1/alerts/rules", json=VALID_RULE, headers=auth_headers)
        assert resp.status_code == 200
        assert "id" in resp.json()

    async def test_create_rule_with_webhook(self, client: AsyncClient, auth_headers: dict):
        rule = {"name": "Webhook Rule", "trigger": "scan_complete",
                "notify_webhook": "https://hooks.example.com/webhook"}
        resp = await client.post("/api/v1/alerts/rules", json=rule, headers=auth_headers)
        assert resp.status_code == 200

    async def test_create_rule_requires_at_least_one_channel(self, client: AsyncClient, auth_headers: dict):
        rule = {"name": "No Channel", "trigger": "critical_finding"}
        resp = await client.post("/api/v1/alerts/rules", json=rule, headers=auth_headers)
        assert resp.status_code == 400

    async def test_create_rule_invalid_trigger(self, client: AsyncClient, auth_headers: dict):
        rule = {**VALID_RULE, "trigger": "invalid_trigger_type"}
        resp = await client.post("/api/v1/alerts/rules", json=rule, headers=auth_headers)
        assert resp.status_code == 422

    async def test_create_rule_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/alerts/rules", json=VALID_RULE)
        assert resp.status_code == 401

    async def test_list_rules_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/alerts/rules", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["rules"] == []

    async def test_list_rules_after_creation(self, client: AsyncClient, auth_headers: dict):
        await client.post("/api/v1/alerts/rules", json=VALID_RULE, headers=auth_headers)
        await client.post("/api/v1/alerts/rules", json={
            **VALID_RULE, "name": "Another Rule", "trigger": "high_finding"
        }, headers=auth_headers)

        resp = await client.get("/api/v1/alerts/rules", headers=auth_headers)
        assert len(resp.json()["rules"]) == 2

    async def test_list_rules_only_own_rules(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        await client.post("/api/v1/alerts/rules", json=VALID_RULE, headers=auth_headers)
        resp = await client.get("/api/v1/alerts/rules", headers=second_auth_headers)
        assert resp.json()["rules"] == []

    async def test_toggle_rule(self, client: AsyncClient, auth_headers: dict):
        create = await client.post("/api/v1/alerts/rules", json=VALID_RULE, headers=auth_headers)
        rule_id = create.json()["id"]

        resp = await client.patch(f"/api/v1/alerts/rules/{rule_id}/toggle", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

        resp2 = await client.patch(f"/api/v1/alerts/rules/{rule_id}/toggle", headers=auth_headers)
        assert resp2.json()["is_active"] is True

    async def test_toggle_rule_not_found(self, client: AsyncClient, auth_headers: dict):
        resp = await client.patch("/api/v1/alerts/rules/no-such-rule/toggle", headers=auth_headers)
        assert resp.status_code == 404

    async def test_delete_rule(self, client: AsyncClient, auth_headers: dict):
        create = await client.post("/api/v1/alerts/rules", json=VALID_RULE, headers=auth_headers)
        rule_id = create.json()["id"]

        del_resp = await client.delete(f"/api/v1/alerts/rules/{rule_id}", headers=auth_headers)
        assert del_resp.status_code == 200

        list_resp = await client.get("/api/v1/alerts/rules", headers=auth_headers)
        assert list_resp.json()["rules"] == []

    async def test_delete_rule_not_found(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/alerts/rules/no-such-rule", headers=auth_headers)
        assert resp.status_code == 404

    async def test_cannot_delete_another_users_rule(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        create = await client.post("/api/v1/alerts/rules", json=VALID_RULE, headers=auth_headers)
        rule_id = create.json()["id"]
        resp = await client.delete(f"/api/v1/alerts/rules/{rule_id}", headers=second_auth_headers)
        assert resp.status_code == 404

    async def test_all_trigger_types_valid(self, client: AsyncClient, auth_headers: dict):
        for trigger in ("scan_complete", "critical_finding", "high_finding", "brute_force", "all"):
            resp = await client.post("/api/v1/alerts/rules", json={
                "name": f"Rule for {trigger}",
                "trigger": trigger,
                "notify_email": "a@b.com",
            }, headers=auth_headers)
            assert resp.status_code == 200, f"Failed for trigger={trigger}: {resp.text}"


class TestWatchlist:
    async def test_add_watchlist_entry(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post("/api/v1/watchlist", json={
            "service_name": "nginx",
            "min_severity": "high",
        }, headers=auth_headers)
        assert resp.status_code == 200
        entry = resp.json()["entry"]
        assert entry["service_name"] == "nginx"
        assert entry["min_severity"] == "high"
        assert entry["is_active"] is True

    async def test_watchlist_service_name_lowercased(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post("/api/v1/watchlist", json={
            "service_name": "NGINX",
            "min_severity": "high",
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["entry"]["service_name"] == "nginx"

    async def test_add_duplicate_watchlist_rejected(self, client: AsyncClient, auth_headers: dict):
        await client.post("/api/v1/watchlist", json={"service_name": "apache", "min_severity": "high"},
                          headers=auth_headers)
        resp = await client.post("/api/v1/watchlist", json={"service_name": "apache", "min_severity": "critical"},
                                 headers=auth_headers)
        assert resp.status_code == 409

    async def test_add_watchlist_invalid_severity(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post("/api/v1/watchlist", json={
            "service_name": "openssh",
            "min_severity": "extreme",
        }, headers=auth_headers)
        assert resp.status_code == 400

    async def test_list_watchlist_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/watchlist", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["entries"] == []

    async def test_list_watchlist_entries(self, client: AsyncClient, auth_headers: dict):
        await client.post("/api/v1/watchlist", json={"service_name": "nginx", "min_severity": "high"},
                          headers=auth_headers)
        await client.post("/api/v1/watchlist", json={"service_name": "openssh", "min_severity": "critical"},
                          headers=auth_headers)
        resp = await client.get("/api/v1/watchlist", headers=auth_headers)
        assert len(resp.json()["entries"]) == 2

    async def test_list_watchlist_only_own_entries(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        await client.post("/api/v1/watchlist", json={"service_name": "nginx", "min_severity": "high"},
                          headers=auth_headers)
        resp = await client.get("/api/v1/watchlist", headers=second_auth_headers)
        assert resp.json()["entries"] == []

    async def test_toggle_watchlist_entry(self, client: AsyncClient, auth_headers: dict):
        create = await client.post("/api/v1/watchlist",
                                   json={"service_name": "nginx", "min_severity": "high"},
                                   headers=auth_headers)
        entry_id = create.json()["entry"]["id"]

        resp = await client.patch(f"/api/v1/watchlist/{entry_id}/toggle", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

        resp2 = await client.patch(f"/api/v1/watchlist/{entry_id}/toggle", headers=auth_headers)
        assert resp2.json()["is_active"] is True

    async def test_toggle_not_found(self, client: AsyncClient, auth_headers: dict):
        resp = await client.patch("/api/v1/watchlist/no-such-id/toggle", headers=auth_headers)
        assert resp.status_code == 404

    async def test_delete_watchlist_entry(self, client: AsyncClient, auth_headers: dict):
        create = await client.post("/api/v1/watchlist",
                                   json={"service_name": "nginx", "min_severity": "high"},
                                   headers=auth_headers)
        entry_id = create.json()["entry"]["id"]

        del_resp = await client.delete(f"/api/v1/watchlist/{entry_id}", headers=auth_headers)
        assert del_resp.status_code == 200

        list_resp = await client.get("/api/v1/watchlist", headers=auth_headers)
        assert list_resp.json()["entries"] == []

    async def test_cannot_delete_another_users_entry(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        create = await client.post("/api/v1/watchlist",
                                   json={"service_name": "nginx", "min_severity": "high"},
                                   headers=auth_headers)
        entry_id = create.json()["entry"]["id"]
        resp = await client.delete(f"/api/v1/watchlist/{entry_id}", headers=second_auth_headers)
        assert resp.status_code == 404

    async def test_watchlist_all_severity_levels(self, client: AsyncClient, auth_headers: dict):
        services = [
            ("svc1", "critical"), ("svc2", "high"),
            ("svc3", "medium"), ("svc4", "low"), ("svc5", "any"),
        ]
        for service, sev in services:
            resp = await client.post("/api/v1/watchlist",
                                     json={"service_name": service, "min_severity": sev},
                                     headers=auth_headers)
            assert resp.status_code == 200, f"Failed for {service}/{sev}: {resp.text}"

    async def test_watchlist_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/watchlist")
        assert resp.status_code == 401
