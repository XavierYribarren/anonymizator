"""SMTP email sending with graceful fallback when not configured."""
import asyncio
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def _cfg(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def is_configured() -> bool:
    return bool(_cfg("SMTP_HOST") and _cfg("SMTP_USER") and _cfg("SMTP_PASSWORD"))


def _send_sync(to: str, subject: str, html_body: str):
    if not is_configured():
        logger.warning("SMTP not configured — skipping email to %s (%s)", to, subject)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = _cfg("SMTP_FROM", f"Anonymizator <{_cfg('SMTP_USER')}>")
    msg["To"] = to
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    host = _cfg("SMTP_HOST")
    port = int(_cfg("SMTP_PORT", "587"))
    use_starttls = _cfg("SMTP_STARTTLS", "true").lower() != "false"

    try:
        if use_starttls:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(_cfg("SMTP_USER"), _cfg("SMTP_PASSWORD"))
                smtp.sendmail(msg["From"], to, msg.as_string())
        else:
            with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
                smtp.login(_cfg("SMTP_USER"), _cfg("SMTP_PASSWORD"))
                smtp.sendmail(msg["From"], to, msg.as_string())
        logger.info("Email sent to %s", to)
    except Exception as exc:
        logger.warning("Failed to send email to %s: %s", to, exc)


async def _send(to: str, subject: str, html_body: str):
    """Non-blocking wrapper — runs SMTP in a thread so the event loop is not blocked."""
    await asyncio.to_thread(_send_sync, to, subject, html_body)


async def send_collector_invitation(to: str, upload_url: str, expires_at: str):
    html = f"""<html><body style="font-family:sans-serif;max-width:600px;margin:auto">
<p>Bonjour,</p>
<p>Vous avez été invité à envoyer un fichier de façon sécurisée.</p>
<p><a href="{upload_url}" style="background:#1a237e;color:white;padding:10px 20px;
   border-radius:5px;text-decoration:none;display:inline-block">
   → Cliquez ici pour envoyer votre fichier
</a></p>
<p>Ce lien est <strong>à usage unique</strong> et expire le {expires_at}.<br>
Vos données seront chiffrées dans votre navigateur avant envoi —
personne d'autre ne peut y accéder.</p>
<hr><small>Anonymizator — chiffrement RSA-4096 + AES-256-GCM côté navigateur</small>
</body></html>"""
    await _send(to, "[Anonymizator] Envoi de fichier sécurisé demandé", html)


async def send_researcher_notification(
    to: str,
    original_filename: str,
    uploaded_at: str,
    expires_at: str,
    base_url: str,
):
    decrypt_url = f"{base_url}/decrypt"
    html = f"""<html><body style="font-family:sans-serif;max-width:600px;margin:auto">
<p>Un fichier chiffré est disponible au téléchargement.</p>
<ul>
  <li><strong>Fichier :</strong> {original_filename}</li>
  <li><strong>Reçu le :</strong> {uploaded_at}</li>
  <li><strong>Expire le :</strong> {expires_at}</li>
</ul>
<p><a href="{decrypt_url}" style="background:#1a237e;color:white;padding:10px 20px;
   border-radius:5px;text-decoration:none;display:inline-block">
   → Télécharger et déchiffrer
</a></p>
<hr><small>Anonymizator — chiffrement RSA-4096 + AES-256-GCM côté navigateur</small>
</body></html>"""
    await _send(
        to,
        f"[Anonymizator] Fichier reçu — {original_filename}",
        html,
    )
