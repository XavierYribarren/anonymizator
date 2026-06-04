"""Tests for web/mailer.py — email sending with graceful SMTP fallback."""
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from web import mailer


class TestIsConfigured:
    def test_false_when_no_smtp_host(self, monkeypatch):
        monkeypatch.delenv("SMTP_HOST", raising=False)
        assert mailer.is_configured() is False

    def test_true_when_all_vars_set(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "secret")
        assert mailer.is_configured() is True

    def test_false_when_password_missing(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)
        assert mailer.is_configured() is False


class TestSendCollectorInvitation:
    async def test_skips_when_not_configured(self):
        """Should not raise even when SMTP is not configured."""
        await mailer.send_collector_invitation(
            to="collector@test.com",
            upload_url="http://testserver/upload/abc123",
            expires_at="2026-12-31T00:00:00+00:00",
        )

    async def test_calls_smtp_when_configured(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.test.com")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_USER", "user@test.com")
        monkeypatch.setenv("SMTP_PASSWORD", "pass")
        monkeypatch.setenv("SMTP_STARTTLS", "true")

        with patch("web.mailer._send_sync") as mock_send:
            await mailer.send_collector_invitation(
                to="collector@test.com",
                upload_url="http://testserver/upload/abc",
                expires_at="2026-12-31T00:00:00+00:00",
            )
            mock_send.assert_called_once()
            args = mock_send.call_args[0]
            assert args[0] == "collector@test.com"
            assert "http://testserver/upload/abc" in args[2]

    async def test_upload_url_in_email_body(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.test.com")
        monkeypatch.setenv("SMTP_USER", "u")
        monkeypatch.setenv("SMTP_PASSWORD", "p")

        captured_html = []
        with patch("web.mailer._send_sync", side_effect=lambda *a: captured_html.append(a[2])):
            await mailer.send_collector_invitation(
                to="c@test.com",
                upload_url="http://testserver/upload/TOKEN_ID",
                expires_at="2026-01-01T00:00:00+00:00",
            )
        assert "http://testserver/upload/TOKEN_ID" in captured_html[0]


class TestSendResearcherNotification:
    async def test_skips_when_not_configured(self):
        await mailer.send_researcher_notification(
            to="researcher@test.com",
            original_filename="data.csv",
            uploaded_at="2026-05-01T12:00:00+00:00",
            expires_at="2026-05-22T12:00:00+00:00",
            base_url="http://testserver",
        )

    async def test_filename_in_subject_and_body(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.test.com")
        monkeypatch.setenv("SMTP_USER", "u")
        monkeypatch.setenv("SMTP_PASSWORD", "p")

        captured = []
        with patch("web.mailer._send_sync", side_effect=lambda *a: captured.append(a)):
            await mailer.send_researcher_notification(
                to="researcher@test.com",
                original_filename="important_data.csv",
                uploaded_at="2026-05-01T12:00:00+00:00",
                expires_at="2026-05-22T12:00:00+00:00",
                base_url="http://testserver",
            )
        subject, html = captured[0][1], captured[0][2]
        assert "important_data.csv" in subject
        assert "important_data.csv" in html
        assert "http://testserver/decrypt" in html


class TestSendSyncFallback:
    def test_does_not_raise_when_smtp_not_configured(self):
        with patch.dict(os.environ, {"SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": ""}):
            mailer._send_sync("to@test.com", "Subject", "<p>Body</p>")

    def test_raises_on_connection_error(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "invalid.host.local")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_USER", "u")
        monkeypatch.setenv("SMTP_PASSWORD", "p")
        monkeypatch.setenv("SMTP_STARTTLS", "true")
        import pytest
        with pytest.raises(Exception):
            mailer._send_sync("to@test.com", "Subject", "<p>Body</p>")

    async def test_send_is_graceful_after_all_retries(self, monkeypatch):
        """_send must not propagate exceptions after exhausting retries."""
        monkeypatch.setenv("SMTP_HOST", "invalid.host.local")
        monkeypatch.setenv("SMTP_USER", "u")
        monkeypatch.setenv("SMTP_PASSWORD", "p")
        with patch("web.mailer._send_sync", side_effect=OSError("refused")):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await mailer._send("to@test.com", "Subject", "<p>Body</p>")
