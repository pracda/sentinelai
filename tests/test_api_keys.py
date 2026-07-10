"""
Tests for user API key management: create, list, revoke, rotate.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import register_user, SERVICE_HEADERS


async def create_key(client: AsyncClient, headers: dict, name: str = "Test Key") -> dict:
    resp = await client.post("/api/v1/user/keys", json={"name": name}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestCreateKey:
    async def test_create_key_returns_raw_key(self, client: AsyncClient, auth_headers: dict):
        data = await create_key(client, auth_headers)
        assert "key" in data
        assert data["key"].startswith("sal_")
        assert "warning" in data
        assert data["prefix"] == data["key"][:12]

    async def test_create_key_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/user/keys", json={"name": "No Auth"})
        assert resp.status_code == 401

    async def test_create_key_name_required(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post("/api/v1/user/keys", json={"name": ""}, headers=auth_headers)
        assert resp.status_code == 422


class TestListKeys:
    async def test_list_keys_empty_initially(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/user/keys", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["keys"] == []

    async def test_list_keys_shows_created_keys(self, client: AsyncClient, auth_headers: dict):
        await create_key(client, auth_headers, "Key A")
        await create_key(client, auth_headers, "Key B")
        resp = await client.get("/api/v1/user/keys", headers=auth_headers)
        assert resp.status_code == 200
        assert len(resp.json()["keys"]) == 2

    async def test_list_keys_only_shows_own_keys(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        await create_key(client, auth_headers, "My Key")
        resp = await client.get("/api/v1/user/keys", headers=second_auth_headers)
        assert resp.json()["keys"] == []


class TestRevokeKey:
    async def test_revoke_key(self, client: AsyncClient, auth_headers: dict):
        created = await create_key(client, auth_headers)
        key_id = created["id"]
        resp = await client.delete(f"/api/v1/user/keys/{key_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert "revoked" in resp.json()["message"].lower()

        list_resp = await client.get("/api/v1/user/keys", headers=auth_headers)
        assert list_resp.json()["keys"] == []

    async def test_revoked_key_cannot_authenticate(self, client: AsyncClient, auth_headers: dict):
        created = await create_key(client, auth_headers)
        raw_key = created["key"]
        key_id = created["id"]

        # Revoke it
        await client.delete(f"/api/v1/user/keys/{key_id}", headers=auth_headers)

        # Try to use the revoked key
        resp = await client.get("/api/v1/scans", headers={"X-API-Key": raw_key})
        assert resp.status_code == 401

    async def test_cannot_revoke_another_users_key(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        created = await create_key(client, auth_headers)
        key_id = created["id"]
        resp = await client.delete(f"/api/v1/user/keys/{key_id}", headers=second_auth_headers)
        assert resp.status_code == 404

    async def test_revoke_nonexistent_key(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/user/keys/nonexistent-id", headers=auth_headers)
        assert resp.status_code == 404


class TestRotateKey:
    async def test_rotate_returns_new_key(self, client: AsyncClient, auth_headers: dict):
        original = await create_key(client, auth_headers, "Rotating Key")
        old_key = original["key"]
        key_id = original["id"]

        resp = await client.post(f"/api/v1/user/keys/{key_id}/rotate", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] != old_key
        assert data["name"] == "Rotating Key"

    async def test_old_key_invalid_after_rotate(self, client: AsyncClient, auth_headers: dict):
        original = await create_key(client, auth_headers)
        old_key = original["key"]
        key_id = original["id"]

        await client.post(f"/api/v1/user/keys/{key_id}/rotate", headers=auth_headers)

        resp = await client.get("/api/v1/scans", headers={"X-API-Key": old_key})
        assert resp.status_code == 401

    async def test_new_key_valid_after_rotate(self, client: AsyncClient, auth_headers: dict):
        original = await create_key(client, auth_headers)
        key_id = original["id"]

        rotate_resp = await client.post(f"/api/v1/user/keys/{key_id}/rotate", headers=auth_headers)
        new_key = rotate_resp.json()["key"]

        resp = await client.get("/api/v1/scans", headers={"X-API-Key": new_key})
        assert resp.status_code == 200

    async def test_cannot_rotate_another_users_key(self, client: AsyncClient, auth_headers: dict, second_auth_headers: dict):
        created = await create_key(client, auth_headers)
        key_id = created["id"]
        resp = await client.post(f"/api/v1/user/keys/{key_id}/rotate", headers=second_auth_headers)
        assert resp.status_code == 404


class TestUserApiKeyAuth:
    async def test_user_key_can_access_scans(self, client: AsyncClient, auth_headers: dict):
        created = await create_key(client, auth_headers)
        raw_key = created["key"]

        resp = await client.get("/api/v1/scans", headers={"X-API-Key": raw_key})
        assert resp.status_code == 200

    async def test_invalid_key_rejected(self, client: AsyncClient):
        resp = await client.get("/api/v1/scans", headers={"X-API-Key": "not-a-real-key"})
        assert resp.status_code == 401
