"""
Email Protocol Layer — sends/receives via standard SMTP/IMAP so the
encrypted payload transits real providers (Gmail etc.) unmodified.
Ciphertext + crypto metadata travels as a JSON blob in the email body;
subject/headers stay in cleartext for routing.
"""

import base64
import imaplib
import json
import os
import smtplib
from email.header import decode_header
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.policy import default as email_default_policy

GMAIL_USER = os.environ.get("QUMAIL_GMAIL_USER")
GMAIL_APP_PASSWORD = os.environ.get("QUMAIL_GMAIL_APP_PASSWORD")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
IMAP_HOST = "imap.gmail.com"

QUMAIL_MARKER = "X-QuMail-Payload"


def _require_credentials():
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "Set QUMAIL_GMAIL_USER and QUMAIL_GMAIL_APP_PASSWORD env vars "
            "(a Gmail App Password, not your normal password) before sending/receiving."
        )


def send_email(to_addr: str, subject: str, payload_json: dict):
    """Send an email whose body carries the QuMail JSON payload as its content."""
    _require_credentials()

    body_text = (
        "This message was sent via QuMail (quantum-secured email client).\n\n"
        f"[{QUMAIL_MARKER}]\n{json.dumps(payload_json)}\n"
    )
    msg = MIMEText(body_text, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = GMAIL_USER
    msg["To"] = to_addr

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, [to_addr], msg.as_string())


def fetch_inbox(limit: int = 20) -> list[dict]:
    """Fetch recent messages, parsing out QuMail payloads where present."""
    _require_credentials()

    results = []
    with imaplib.IMAP4_SSL(IMAP_HOST) as imap:
        imap.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        imap.select("INBOX")
        status, data = imap.search(None, "ALL")
        if status != "OK":
            return results
        msg_ids = data[0].split()[-limit:]
        for mid in reversed(msg_ids):
            status, msg_data = imap.fetch(mid, "(RFC822)")
            if status != "OK":
                continue
            raw = msg_data[0][1]
            parsed = BytesParser(policy=email_default_policy).parsebytes(raw)
            subject = str(parsed["subject"] or "(no subject)")
            sender = str(parsed["from"] or "")
            body = ""
            if parsed.is_multipart():
                for part in parsed.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_content()
                        break
            else:
                body = parsed.get_content()

            payload = None
            if QUMAIL_MARKER in body:
                try:
                    json_part = body.split(f"[{QUMAIL_MARKER}]", 1)[1].strip()
                    payload = json.loads(json_part.splitlines()[0])
                except Exception:
                    payload = None

            results.append({
                "id": mid.decode(),
                "subject": subject,
                "from": sender,
                "body": body,
                "qumail_payload": payload,
                "is_qumail": payload is not None,
            })
    return results
