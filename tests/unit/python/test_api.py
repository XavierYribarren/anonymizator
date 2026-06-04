"""Tests for FastAPI routes in web/main.py."""
import pytest


class TestTokenAPI:
    async def test_create_token_success(self, client, sample_key_pair):
        resp = await client.post("/api/tokens", json={
            "public_key": sample_key_pair["public"],
            "researcher_email": "researcher@test.com",
            "collector_email": "collector@test.com",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "token_id" in data
        assert "upload_url" in data
        assert data["upload_url"].startswith("http")
        assert "expires_at" in data
        assert "researcher_token" in data
        assert len(data["researcher_token"]) == 36  # UUID4

    async def test_create_token_same_key_reuses_researcher_token(self, client, sample_key_pair):
        """Two tokens for the same public key share the same researcher_token."""
        payload = {"public_key": sample_key_pair["public"]}
        r1 = (await client.post("/api/tokens", json=payload)).json()
        r2 = (await client.post("/api/tokens", json=payload)).json()
        assert r1["researcher_token"] == r2["researcher_token"]

    async def test_create_token_no_researcher_email(self, client, sample_key_pair):
        resp = await client.post("/api/tokens", json={
            "public_key": sample_key_pair["public"],
            "collector_email": "collector@test.com",
        })
        assert resp.status_code == 200

    async def test_create_token_invalid_key(self, client):
        resp = await client.post("/api/tokens", json={
            "public_key": "not-a-valid-pem",
            "collector_email": "collector@test.com",
        })
        assert resp.status_code in (400, 422)

    async def test_create_token_missing_collector_email(self, client, sample_key_pair):
        resp = await client.post("/api/tokens", json={
            "public_key": sample_key_pair["public"],
        })
        assert resp.status_code == 200

    async def test_get_token_valid(self, client, sample_token):
        token_id, *_ = await sample_token()
        resp = await client.get(f"/api/tokens/{token_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["used"] is False
        assert data["expired"] is False

    async def test_get_token_nonexistent_returns_200_invalid(self, client):
        resp = await client.get("/api/tokens/00000000-does-not-exist")
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    async def test_get_token_public_key(self, client, sample_token, sample_key_pair):
        token_id, *_ = await sample_token()
        resp = await client.get(f"/api/tokens/{token_id}/public-key")
        assert resp.status_code == 200
        assert "public_key" in resp.json()

    async def test_get_public_key_nonexistent_returns_404(self, client):
        resp = await client.get("/api/tokens/nonexistent/public-key")
        assert resp.status_code == 404


class TestUploadAPI:
    async def test_upload_success(self, client, sample_token):
        token_id, *_ = await sample_token()
        enc = b"\x00" * 540
        resp = await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("data.csv.enc", enc, "application/octet-stream")},
            data={"original_filename": "data.csv"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    async def test_upload_marks_token_used(self, client, sample_token):
        token_id, *_ = await sample_token()
        enc = b"\x00" * 540
        await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("f.enc", enc, "application/octet-stream")},
        )
        status_resp = await client.get(f"/api/tokens/{token_id}")
        assert status_resp.json()["used"] is True

    async def test_upload_already_used_token_returns_409(self, client, sample_token):
        token_id, *_ = await sample_token()
        enc = b"\x00" * 540
        await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("a.enc", enc, "application/octet-stream")},
        )
        resp = await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("b.enc", enc, "application/octet-stream")},
        )
        assert resp.status_code == 409

    async def test_upload_invalid_token_returns_404(self, client):
        resp = await client.post(
            "/api/upload/nonexistent-token-xyz",
            files={"file": ("f.enc", b"\x00" * 100, "application/octet-stream")},
        )
        assert resp.status_code == 404

    async def test_upload_file_too_large_returns_413(self, client, sample_token):
        import os
        max_mb = int(os.environ["MAX_FILE_SIZE_MB"])
        token_id, *_ = await sample_token()
        too_large = b"\x00" * ((max_mb + 1) * 1024 * 1024)
        resp = await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("big.enc", too_large, "application/octet-stream")},
        )
        assert resp.status_code == 413


class TestFilesAPI:
    async def test_list_files_empty_for_token(self, client, sample_token):
        _, _, rt = await sample_token()
        resp = await client.get("/api/files",
                                headers={"X-Researcher-Token": rt})
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_files_without_token_returns_401(self, client):
        resp = await client.get("/api/files")
        assert resp.status_code == 401

    async def test_list_files_after_upload(self, client, sample_token):
        token_id, _, rt = await sample_token()
        enc = b"\x00" * 540
        await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("test.enc", enc, "application/octet-stream")},
            data={"original_filename": "test.csv"},
        )
        resp = await client.get("/api/files",
                                headers={"X-Researcher-Token": rt})
        assert resp.status_code == 200
        files = resp.json()
        assert len(files) == 1
        assert files[0]["original_filename"] == "test.csv"

    async def test_download_file_without_token_returns_401(self, client):
        resp = await client.get("/api/files/any-file-id")
        assert resp.status_code == 401

    async def test_download_file_wrong_token_returns_401(self, client, sample_token):
        token_id, *_ = await sample_token()
        enc = b"\x00" * 540
        await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("f.enc", enc, "application/octet-stream")},
        )
        resp = await client.get(
            "/api/files/any-id",
            headers={"X-Researcher-Token": "00000000-0000-0000-0000-000000000000"},
        )
        assert resp.status_code == 401

    async def test_delete_file_wrong_token_returns_401(self, client, sample_token):
        token_id, *_ = await sample_token()
        enc = b"\x00" * 540
        await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("f.enc", enc, "application/octet-stream")},
        )
        resp = await client.delete(
            "/api/files/any-id",
            headers={"X-Researcher-Token": "00000000-0000-0000-0000-000000000001"},
        )
        assert resp.status_code == 401

    async def test_delete_file_correct_token(self, client, sample_token):
        token_id, _, rt = await sample_token()
        enc = b"\x00" * 540
        await client.post(
            f"/api/upload/{token_id}",
            files={"file": ("f.enc", enc, "application/octet-stream")},
        )
        files = (await client.get("/api/files",
                                  headers={"X-Researcher-Token": rt})).json()
        file_id = files[0]["id"]
        resp = await client.delete(f"/api/files/{file_id}",
                                   headers={"X-Researcher-Token": rt})
        assert resp.status_code == 200
        remaining = (await client.get("/api/files",
                                      headers={"X-Researcher-Token": rt})).json()
        assert remaining == []


class TestSecurityHeaders:
    async def test_x_content_type_options(self, client):
        resp = await client.get("/")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    async def test_x_frame_options(self, client):
        resp = await client.get("/")
        assert resp.headers.get("x-frame-options") == "DENY"

    async def test_referrer_policy(self, client):
        resp = await client.get("/")
        assert resp.headers.get("referrer-policy") == "same-origin"

    async def test_permissions_policy(self, client):
        resp = await client.get("/")
        assert "permissions-policy" in resp.headers


class TestActiveTokensCap:
    async def test_cap_enforced_at_50(self, client, sample_key_pair):
        from web import database as db
        from web.main import MAX_ACTIVE_TOKENS, _public_key_fingerprint

        fp = _public_key_fingerprint(sample_key_pair["public"])
        for _ in range(MAX_ACTIVE_TOKENS):
            await db.create_token(
                public_key=sample_key_pair["public"],
                public_key_fingerprint=fp,
                researcher_email=None,
                collector_email="c@test.com",
            )
        resp = await client.post("/api/tokens", json={
            "public_key": sample_key_pair["public"],
            "collector_email": "c@test.com",
        })
        assert resp.status_code == 429
