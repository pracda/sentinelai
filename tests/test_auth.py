"""
Tests for user authentication: register, login, /me, brute-force lockout.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.conftest import register_user


class TestRegister:
    async def test_first_user_becomes_admin(self, client: AsyncClient):
        token, user = await register_user(client)
        assert user["is_admin"] is True
        assert user["username"] == "testuser"

    async def test_second_user_is_not_admin(self, client: AsyncClient):
        await register_user(client)
        _, user2 = await register_user(client, "user2", "u2@example.com", "pass12345")
        assert user2["is_admin"] is False

    async def test_register_returns_jwt(self, client: AsyncClient):
        token, _ = await register_user(client)
        assert token and len(token) > 10

    async def test_duplicate_username_rejected(self, client: AsyncClient):
        await register_user(client)
        resp = await client.post("/api/v1/auth/register", json={
            "username": "testuser",
            "email": "different@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 409

    async def test_duplicate_email_rejected(self, client: AsyncClient):
        await register_user(client)
        resp = await client.post("/api/v1/auth/register", json={
            "username": "otheruser",
            "email": "test@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 409

    async def test_username_too_short(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "username": "ab",
            "email": "short@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 422

    async def test_password_too_short(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "username": "validuser",
            "email": "valid@example.com",
            "password": "short",
        })
        assert resp.status_code == 422

    async def test_invalid_username_chars(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "username": "bad user!",
            "email": "bad@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 422


class TestLogin:
    async def test_login_success(self, client: AsyncClient):
        await register_user(client)
        resp = await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["user"]["email"] == "test@example.com"

    async def test_wrong_password(self, client: AsyncClient):
        await register_user(client)
        resp = await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401

    async def test_nonexistent_user(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/login", json={
            "email": "nobody@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 401

    async def test_brute_force_lockout(self, client: AsyncClient):
        await register_user(client)
        for _ in range(5):
            await client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "wrongpassword",
            })
        resp = await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "wrongpassword",
        })
        assert resp.status_code == 429
        assert "Too many" in resp.json()["detail"]

    async def test_successful_login_clears_brute_force(self, client: AsyncClient):
        await register_user(client)
        for _ in range(3):
            await client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "wrong",
            })
        resp = await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 200


class TestMe:
    async def test_me_returns_user_profile(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert "active_api_keys" in data

    async def test_me_without_auth_rejected(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_me_with_invalid_token(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer this-is-not-a-valid-jwt"},
        )
        assert resp.status_code == 401


class TestHealth:
    async def test_health_check_public(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    async def test_root_returns_app_info(self, client: AsyncClient):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert resp.json()["name"] == "SentinelAI"
