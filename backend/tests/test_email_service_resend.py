import logging
import pytest
from unittest.mock import patch, AsyncMock
import httpx

from app.config import get_settings
from app.services.email_service import (
    EmailService,
    test_outbox,
    generate_auth_token,
    hash_auth_token,
    _build_verification_email_html,
    _build_verification_email_text,
    _build_password_reset_email_html,
    _build_password_reset_email_text,
)

settings = get_settings()


@pytest.fixture(autouse=True)
def clean_outbox():
    """Ensure test outbox is clean before and after each test."""
    test_outbox.clear()
    yield
    test_outbox.clear()


# =====================================================================
# 1. Template Generation & Brand Safety Tests
# =====================================================================

def test_verification_email_template_contains_required_fields():
    """Verification email templates must include brand, link, expiration, and disregard instructions."""
    link = "https://sentriq-rouge.vercel.app/#/verify-email?token=test_token_123"
    html = _build_verification_email_html(link, "Sentriq")
    text = _build_verification_email_text(link, "Sentriq")

    # HTML assertions
    assert "Sentriq" in html
    assert link in html
    assert "24 hours" in html
    assert "safely ignore this email" in html
    assert "Verify Email Address" in html
    assert "EMAIL VERIFICATION" in html

    # Text assertions
    assert "Sentriq" in text
    assert link in text
    assert "24 hours" in text
    assert "safely ignore" in text


def test_password_reset_email_template_contains_required_fields():
    """Password reset email templates must include brand, link, expiration, single-use, and disregard instructions."""
    link = "https://sentriq-rouge.vercel.app/#/reset-password?token=reset_token_456"
    html = _build_password_reset_email_html(link, "Sentriq")
    text = _build_password_reset_email_text(link, "Sentriq")

    # HTML assertions
    assert "Sentriq" in html
    assert link in html
    assert "1 hour" in html
    assert "only be used once" in html
    assert "safely ignore this email" in html
    assert "Reset Password" in html
    assert "PASSWORD RECOVERY" in html

    # Text assertions
    assert "Sentriq" in text
    assert link in text
    assert "1 hour" in text
    assert "only be used once" in text
    assert "safely ignore" in text


# =====================================================================
# 2. Resend API Dispatch & Mock Tests
# =====================================================================

@pytest.mark.asyncio
async def test_resend_verification_email_dispatch_success():
    """Successful Resend API call returns True and records to test outbox."""
    raw_token = generate_auth_token()
    email = "analyst@security-corp.org"

    mock_resp = httpx.Response(
        status_code=200,
        json={"id": "resend_msg_test_001"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        original_key = settings.RESEND_API_KEY
        try:
            settings.RESEND_API_KEY = "re_test_dummy_key_123"
            success = await EmailService.send_verification_email(
                to_email=email,
                raw_token=raw_token,
                force_delivery=True,
            )
            assert success is True
            assert mock_post.called

            # Validate HTTP payload
            called_args, called_kwargs = mock_post.call_args
            assert called_args[0] == "https://api.resend.com/emails"
            assert "Bearer re_test_dummy_key_123" in called_kwargs["headers"]["Authorization"]
            assert called_kwargs["json"]["to"] == [email]
            assert "Verify your Sentriq account" in called_kwargs["json"]["subject"]
            assert raw_token in called_kwargs["json"]["html"]

            # Outbox still recorded message
            assert test_outbox.get_latest_token_for(email) == raw_token
        finally:
            settings.RESEND_API_KEY = original_key


@pytest.mark.asyncio
async def test_resend_password_reset_email_dispatch_success():
    """Successful password reset dispatch via Resend returns True and records to outbox."""
    raw_token = generate_auth_token()
    email = "admin@defense-firm.com"

    mock_resp = httpx.Response(
        status_code=200,
        json={"id": "resend_msg_test_002"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        original_key = settings.RESEND_API_KEY
        try:
            settings.RESEND_API_KEY = "re_test_dummy_key_123"
            success = await EmailService.send_password_reset_email(
                to_email=email,
                raw_token=raw_token,
                force_delivery=True,
            )
            assert success is True
            assert mock_post.called

            called_args, called_kwargs = mock_post.call_args
            assert called_kwargs["json"]["to"] == [email]
            assert "Reset your Sentriq password" in called_kwargs["json"]["subject"]
            assert raw_token in called_kwargs["json"]["html"]
            assert test_outbox.get_latest_token_for(email) == raw_token
        finally:
            settings.RESEND_API_KEY = original_key


@pytest.mark.asyncio
async def test_resend_provider_failure_handled_gracefully():
    """When Resend returns an error status (e.g. 403 domain unverified), EmailService fails safely without exception."""
    raw_token = generate_auth_token()
    email = "lead@enterprise.net"

    mock_resp = httpx.Response(
        status_code=403,
        json={"statusCode": 403, "message": "Domain 'sentriq.io' not verified in Resend dashboard"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        original_key = settings.RESEND_API_KEY
        try:
            settings.RESEND_API_KEY = "re_test_dummy_key_123"
            success = await EmailService.send_verification_email(
                to_email=email,
                raw_token=raw_token,
                force_delivery=True,
            )
            assert success is False
        finally:
            settings.RESEND_API_KEY = original_key


@pytest.mark.asyncio
async def test_resend_network_timeout_handled_gracefully():
    """When HTTP request times out, EmailService catches the timeout and returns False safely."""
    raw_token = generate_auth_token()
    email = "tester@timeout.io"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.TimeoutException("Connection timed out after 10s")
        original_key = settings.RESEND_API_KEY
        try:
            settings.RESEND_API_KEY = "re_test_dummy_key_123"
            success = await EmailService.send_verification_email(
                to_email=email,
                raw_token=raw_token,
                force_delivery=True,
            )
            assert success is False
        finally:
            settings.RESEND_API_KEY = original_key


@pytest.mark.asyncio
async def test_resend_missing_api_key_in_production():
    """In production environment without RESEND_API_KEY, delivery fails safely and logs warning."""
    raw_token = generate_auth_token()
    email = "user@prod-audit.com"

    original_env = settings.ENVIRONMENT
    original_key = settings.RESEND_API_KEY
    try:
        settings.ENVIRONMENT = "production"
        settings.RESEND_API_KEY = None

        success = await EmailService.send_verification_email(
            to_email=email,
            raw_token=raw_token,
        )
        assert success is False
        # Outbox still recorded for audit trail
        assert test_outbox.get_latest_token_for(email) == raw_token
    finally:
        settings.ENVIRONMENT = original_env
        settings.RESEND_API_KEY = original_key


@pytest.mark.asyncio
async def test_resend_missing_api_key_in_development_captures_in_outbox():
    """In development or test environment without RESEND_API_KEY, message is captured in outbox and returns True."""
    raw_token = generate_auth_token()
    email = "dev@local.test"

    original_env = settings.ENVIRONMENT
    original_key = settings.RESEND_API_KEY
    try:
        settings.ENVIRONMENT = "development"
        settings.RESEND_API_KEY = None

        success = await EmailService.send_verification_email(
            to_email=email,
            raw_token=raw_token,
        )
        assert success is True
        assert test_outbox.get_latest_token_for(email) == raw_token
    finally:
        settings.ENVIRONMENT = original_env
        settings.RESEND_API_KEY = original_key


# =====================================================================
# 3. Log Hygiene & Secret Isolation Tests
# =====================================================================

@pytest.mark.asyncio
async def test_no_raw_tokens_or_secrets_leaked_in_logs(caplog):
    """Raw verification tokens and API keys must NEVER appear in server logs."""
    raw_token = "SUPER_SECRET_RAW_TOKEN_999888777"
    dummy_key = "re_SENSITIVE_SECRET_API_KEY_xyz"
    email = "confidential@target-agency.gov"

    mock_resp = httpx.Response(
        status_code=200,
        json={"id": "resend_msg_test_003"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        original_key = settings.RESEND_API_KEY
        try:
            settings.RESEND_API_KEY = dummy_key
            with caplog.at_level(logging.DEBUG):
                await EmailService.send_verification_email(
                    to_email=email,
                    raw_token=raw_token,
                    force_delivery=True,
                )
                await EmailService.send_password_reset_email(
                    to_email=email,
                    raw_token=raw_token,
                    force_delivery=True,
                )

            # Assert raw secrets are NOT in logs
            assert raw_token not in caplog.text, "Raw auth token leaked in log messages!"
            assert dummy_key not in caplog.text, "Resend API key leaked in log messages!"
            # Only the domain should appear
            assert "target-agency.gov" in caplog.text
        finally:
            settings.RESEND_API_KEY = original_key

