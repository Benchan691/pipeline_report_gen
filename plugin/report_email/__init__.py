"""Reusable SMTP client for sending emails with a link in the body."""

from __future__ import annotations

import json
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = PACKAGE_ROOT / "config.json"

__all__ = [
    "EmailConfig",
    "SmtpConfig",
    "build_link_body",
    "load_email_config",
    "require_smtp_config",
    "send_link_email",
]


@dataclass(frozen=True)
class EmailConfig:
    email_title: str
    email_body: str


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    use_tls: bool = True
    use_ssl: bool = False


def load_email_config(path=None) -> EmailConfig:
    config_path = Path(path or DEFAULT_CONFIG)
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return EmailConfig(
        email_title=str(data.get("email_title") or "報告").strip(),
        email_body=str(data.get("email_body") or "Report link below."),
    )


def build_link_body(body: str, link_url: str) -> str:
    text = str(body or "Report link below.").rstrip()
    link_url = str(link_url or "").strip()
    if not link_url:
        raise ValueError("Missing share URL for email")
    return f"{text}\n\n{link_url}"


def require_smtp_config(smtp: SmtpConfig, *, to: str) -> None:
    receiver = str(to or "").strip()
    sender = str(smtp.from_addr or smtp.username or "").strip()
    missing = []
    if not receiver:
        missing.append("to")
    if not smtp.host:
        missing.append("smtp.host")
    if not sender:
        missing.append("smtp.from_addr or smtp.username")
    if missing:
        raise ValueError("Missing email config: " + ", ".join(missing))


def send_link_email(
    smtp: SmtpConfig,
    *,
    to: str,
    subject: str,
    body: str,
    link_url: str,
    smtp_factory=None,
) -> None:
    require_smtp_config(smtp, to=to)
    message = EmailMessage()
    sender = smtp.from_addr or smtp.username
    message["From"] = sender
    message["To"] = to
    message["Subject"] = str(subject or "Report").strip()
    message.set_content(build_link_body(body, link_url))

    smtp_class = smtp_factory or (smtplib.SMTP_SSL if smtp.use_ssl else smtplib.SMTP)
    with smtp_class(smtp.host, int(smtp.port or 587), timeout=30) as client:
        if smtp.use_tls and not smtp.use_ssl:
            client.starttls()
        if smtp.username and smtp.password:
            try:
                client.login(smtp.username, smtp.password)
            except smtplib.SMTPNotSupportedError:
                pass
        client.send_message(message)
