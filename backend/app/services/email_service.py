import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional
import httpx
from app.config import get_settings

logger = logging.getLogger("sentriq.services.email")
settings = get_settings()


def generate_auth_token() -> str:
    """Generate a cryptographically secure 256-bit URL-safe token.

    Security Guarantee:
    - Never expose raw tokens in persistent storage or production logs.
    - Callers MUST store only the SHA-256 hash returned by hash_auth_token().
    """
    return secrets.token_urlsafe(32)


def hash_auth_token(raw_token: str) -> str:
    """Compute constant SHA-256 hex digest of a raw authentication token."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


class EmailOutbox:
    """In-memory outbox for testing and local inspection without exposing secrets to production logs."""

    def __init__(self):
        self._sent_messages: List[Dict[str, str]] = []

    def record(self, to_email: str, subject: str, link: str, raw_token: str) -> None:
        self._sent_messages.append({
            "to_email": to_email,
            "subject": subject,
            "link": link,
            "raw_token": raw_token,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        })

    def clear(self) -> None:
        self._sent_messages.clear()

    def get_messages_for(self, email: str) -> List[Dict[str, str]]:
        clean = email.strip().lower()
        return [m for m in self._sent_messages if m["to_email"].strip().lower() == clean]

    def get_latest_token_for(self, email: str) -> Optional[str]:
        msgs = self.get_messages_for(email)
        return msgs[-1]["raw_token"] if msgs else None

    def get_all_messages(self) -> List[Dict[str, str]]:
        return list(self._sent_messages)


# Global test outbox for test suites
test_outbox = EmailOutbox()


# =====================================================================
# HTML & Plaintext Email Template Generators
# =====================================================================

def _build_verification_email_html(verification_link: str, app_name: str) -> str:
    """Render a professional, dark-themed responsive verification email matching Sentriq brand."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your {app_name} account</title>
</head>
<body style="margin: 0; padding: 0; background-color: #090d16; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #e2e8f0; line-height: 1.6;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #090d16; padding: 40px 15px;">
    <tr>
      <td align="center">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 560px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
          <!-- Header Banner -->
          <tr>
            <td style="padding: 28px 36px; border-bottom: 1px solid #1e293b; background: linear-gradient(180deg, #131d36 0%, #0f172a 100%);">
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="display: inline-block; font-size: 1.15rem; font-weight: 800; letter-spacing: 0.1em; color: #06b6d4; text-transform: uppercase;">
                      {app_name.upper()}
                    </span>
                    <div style="font-size: 0.72rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-top: 2px;">
                      Application Security Intelligence
                    </div>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; background-color: rgba(6, 182, 212, 0.12); color: #06b6d4; border: 1px solid rgba(6, 182, 212, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em;">
                      EMAIL VERIFICATION
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Body Content -->
          <tr>
            <td style="padding: 36px 36px 28px 36px;">
              <h1 style="margin: 0 0 16px 0; font-size: 1.4rem; font-weight: 700; color: #f8fafc; letter-spacing: -0.01em;">
                Confirm your email address
              </h1>
              <p style="margin: 0 0 24px 0; font-size: 0.92rem; color: #94a3b8; line-height: 1.6;">
                Thank you for creating an account on <strong style="color: #f1f5f9;">{app_name}</strong>. To finalize your account setup and access complete security intelligence features, please confirm your email address.
              </p>
              <!-- Action Button -->
              <table border="0" cellspacing="0" cellpadding="0" style="margin: 32px 0;">
                <tr>
                  <td align="center" style="border-radius: 8px; background-color: #06b6d4;">
                    <a href="{verification_link}" target="_blank" rel="noopener noreferrer" style="display: inline-block; padding: 13px 32px; font-size: 0.9rem; font-weight: 700; color: #090d16; text-decoration: none; border-radius: 8px; letter-spacing: 0.02em;">
                      Verify Email Address &rarr;
                    </a>
                  </td>
                </tr>
              </table>
              <p style="margin: 0 0 12px 0; font-size: 0.8rem; color: #64748b;">
                Or paste this link into your browser:
              </p>
              <div style="background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 0.76rem; color: #38bdf8; word-break: break-all; margin-bottom: 28px;">
                {verification_link}
              </div>
              <div style="padding: 14px 16px; background-color: rgba(245, 158, 11, 0.08); border-left: 3px solid #f59e0b; border-radius: 4px; font-size: 0.78rem; color: #fbbf24; margin-bottom: 12px;">
                <strong>Expiration Notice:</strong> This link will expire in 24 hours and can only be used once.
              </div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 24px 36px 32px 36px; border-top: 1px solid #1e293b; background-color: #0b1120;">
              <p style="margin: 0 0 8px 0; font-size: 0.74rem; color: #64748b; line-height: 1.5;">
                <strong>Didn't sign up for {app_name}?</strong> You can safely ignore this email. No account will be activated without verification.
              </p>
              <p style="margin: 0; font-size: 0.7rem; color: #475569;">
                &copy; {datetime.now(timezone.utc).year} {app_name} Security Intelligence. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _build_verification_email_text(verification_link: str, app_name: str) -> str:
    """Render plaintext verification email."""
    return f"""Verify your {app_name} account

Thank you for creating an account on {app_name}. To complete registration, please verify your email address by visiting the link below:

{verification_link}

This verification link will expire in 24 hours.

If you did not create a {app_name} account, you can safely ignore this message.

--
{app_name} Application Security Intelligence
"""


def _build_password_reset_email_html(reset_link: str, app_name: str) -> str:
    """Render a professional, dark-themed responsive password reset email matching Sentriq brand."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset your {app_name} password</title>
</head>
<body style="margin: 0; padding: 0; background-color: #090d16; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #e2e8f0; line-height: 1.6;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #090d16; padding: 40px 15px;">
    <tr>
      <td align="center">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 560px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
          <!-- Header Banner -->
          <tr>
            <td style="padding: 28px 36px; border-bottom: 1px solid #1e293b; background: linear-gradient(180deg, #131d36 0%, #0f172a 100%);">
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="display: inline-block; font-size: 1.15rem; font-weight: 800; letter-spacing: 0.1em; color: #06b6d4; text-transform: uppercase;">
                      {app_name.upper()}
                    </span>
                    <div style="font-size: 0.72rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-top: 2px;">
                      Application Security Intelligence
                    </div>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; background-color: rgba(244, 63, 94, 0.12); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em;">
                      PASSWORD RECOVERY
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Body Content -->
          <tr>
            <td style="padding: 36px 36px 28px 36px;">
              <h1 style="margin: 0 0 16px 0; font-size: 1.4rem; font-weight: 700; color: #f8fafc; letter-spacing: -0.01em;">
                Reset your password
              </h1>
              <p style="margin: 0 0 24px 0; font-size: 0.92rem; color: #94a3b8; line-height: 1.6;">
                We received a request to reset the password for your <strong style="color: #f1f5f9;">{app_name}</strong> account. Click the button below to choose a new password.
              </p>
              <!-- Action Button -->
              <table border="0" cellspacing="0" cellpadding="0" style="margin: 32px 0;">
                <tr>
                  <td align="center" style="border-radius: 8px; background-color: #06b6d4;">
                    <a href="{reset_link}" target="_blank" rel="noopener noreferrer" style="display: inline-block; padding: 13px 32px; font-size: 0.9rem; font-weight: 700; color: #090d16; text-decoration: none; border-radius: 8px; letter-spacing: 0.02em;">
                      Reset Password &rarr;
                    </a>
                  </td>
                </tr>
              </table>
              <p style="margin: 0 0 12px 0; font-size: 0.8rem; color: #64748b;">
                Or paste this link into your browser:
              </p>
              <div style="background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 0.76rem; color: #38bdf8; word-break: break-all; margin-bottom: 28px;">
                {reset_link}
              </div>
              <div style="padding: 14px 16px; background-color: rgba(245, 158, 11, 0.08); border-left: 3px solid #f59e0b; border-radius: 4px; font-size: 0.78rem; color: #fbbf24; margin-bottom: 12px;">
                <strong>Security Notice:</strong> This password reset link is valid for <strong>1 hour</strong> and can only be used once. Resetting your password will automatically invalidate all existing active sessions.
              </div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 24px 36px 32px 36px; border-top: 1px solid #1e293b; background-color: #0b1120;">
              <p style="margin: 0 0 8px 0; font-size: 0.74rem; color: #64748b; line-height: 1.5;">
                <strong>Didn't request this?</strong> If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged and your account is secure.
              </p>
              <p style="margin: 0; font-size: 0.7rem; color: #475569;">
                &copy; {datetime.now(timezone.utc).year} {app_name} Security Intelligence. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _build_password_reset_email_text(reset_link: str, app_name: str) -> str:
    """Render plaintext password reset email."""
    return f"""Reset your {app_name} password

We received a request to reset the password for your {app_name} account.

To reset your password, visit the link below:

{reset_link}

This link is valid for 1 hour and can only be used once. Confirming a password reset will automatically revoke all existing active sessions.

If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged.

--
{app_name} Application Security Intelligence
"""


# =====================================================================
# Resend API Delivery Engine
# =====================================================================

async def _deliver_via_resend(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str,
    api_key: Optional[str] = None,
    from_email: Optional[str] = None,
) -> bool:
    """Dispatch email via Resend HTTPS REST API.

    Security Guarantees:
    - Never logs raw tokens or authorization headers.
    - Masks recipient email to domain-only in application logs.
    - Handles timeouts and provider failures safely without exposing internals.
    """
    key = api_key or settings.RESEND_API_KEY
    sender = from_email or settings.EMAIL_FROM
    domain = to_email.split("@")[-1] if "@" in to_email else "unknown"

    if not key:
        logger.warning("Resend API key missing; skipping dispatch to recipient domain: %s", domain)
        return False

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": f"{settings.APP_NAME}-EmailService/{settings.APP_VERSION}",
    }
    payload = {
        "from": sender,
        "to": [to_email],
        "subject": subject,
        "html": html_content,
        "text": text_content,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("https://api.resend.com/emails", json=payload, headers=headers)
            if resp.status_code in (200, 201):
                data = resp.json()
                email_id = data.get("id", "unknown")
                logger.info("Email delivered successfully via Resend [id=%s] to domain: %s", email_id, domain)
                return True
            else:
                err_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                err_msg = err_data.get("message") or resp.text[:200]
                logger.error(
                    "Resend email delivery failed (status=%d): %s (domain=%s)",
                    resp.status_code,
                    err_msg,
                    domain,
                )
                return False
    except httpx.TimeoutException:
        logger.error("Resend email delivery timed out after 10s (domain=%s)", domain)
        return False
    except Exception as e:
        logger.error("Resend email delivery exception (domain=%s): %s", domain, type(e).__name__)
        return False


# =====================================================================
# Public Email Service Interface
# =====================================================================

class EmailService:
    """Enterprise email notification service for verification and recovery workflows."""

    @staticmethod
    async def send_verification_email(
        to_email: str,
        raw_token: str,
        force_delivery: bool = False,
    ) -> bool:
        """Dispatch email verification link.

        In all environments, the message is recorded in test_outbox for test assertions.
        In production (or when force_delivery=True), real delivery is executed via Resend API.
        Raw token is never written to server logs.
        """
        base_url = settings.FRONTEND_URL.rstrip("/")
        verification_link = f"{base_url}/#/verify-email?token={raw_token}"
        subject = f"Verify your {settings.APP_NAME} account"

        # Record in test outbox for test assertions & local inspection
        test_outbox.record(
            to_email=to_email,
            subject=subject,
            link=verification_link,
            raw_token=raw_token,
        )

        domain = to_email.split("@")[-1] if "@" in to_email else "unknown"
        html_body = _build_verification_email_html(verification_link, settings.APP_NAME)
        text_body = _build_verification_email_text(verification_link, settings.APP_NAME)

        # Decide whether to execute real Resend delivery
        should_deliver = force_delivery or (settings.ENVIRONMENT == "production" and bool(settings.RESEND_API_KEY))

        if should_deliver:
            return await _deliver_via_resend(
                to_email=to_email,
                subject=subject,
                html_content=html_body,
                text_content=text_body,
            )

        if settings.ENVIRONMENT == "production" and not settings.RESEND_API_KEY:
            logger.warning("RESEND_API_KEY not configured in production; email delivery skipped for domain: %s", domain)
            return False

        logger.debug("Captured verification email for domain %s in local outbox.", domain)
        return True

    @staticmethod
    async def send_password_reset_email(
        to_email: str,
        raw_token: str,
        force_delivery: bool = False,
    ) -> bool:
        """Dispatch password recovery link.

        In all environments, the message is recorded in test_outbox for test assertions.
        In production (or when force_delivery=True), real delivery is executed via Resend API.
        Raw token is never written to server logs.
        """
        base_url = settings.FRONTEND_URL.rstrip("/")
        reset_link = f"{base_url}/#/reset-password?token={raw_token}"
        subject = f"Reset your {settings.APP_NAME} password"

        # Record in test outbox for test assertions & local inspection
        test_outbox.record(
            to_email=to_email,
            subject=subject,
            link=reset_link,
            raw_token=raw_token,
        )

        domain = to_email.split("@")[-1] if "@" in to_email else "unknown"
        html_body = _build_password_reset_email_html(reset_link, settings.APP_NAME)
        text_body = _build_password_reset_email_text(reset_link, settings.APP_NAME)

        # Decide whether to execute real Resend delivery
        should_deliver = force_delivery or (settings.ENVIRONMENT == "production" and bool(settings.RESEND_API_KEY))

        if should_deliver:
            return await _deliver_via_resend(
                to_email=to_email,
                subject=subject,
                html_content=html_body,
                text_content=text_body,
            )

        if settings.ENVIRONMENT == "production" and not settings.RESEND_API_KEY:
            logger.warning("RESEND_API_KEY not configured in production; email delivery skipped for domain: %s", domain)
            return False

        logger.debug("Captured password reset email for domain %s in local outbox.", domain)
        return True
