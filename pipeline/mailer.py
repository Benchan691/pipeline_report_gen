import mimetypes
import os
import smtplib
from email.message import EmailMessage


def require_email_config(cfg):
    receiver = cfg.get("email_receiver")
    sender = cfg.get("SMTP_FROM") or cfg.get("SMTP_USERNAME")
    missing = []
    if not receiver:
        missing.append("email_receiver")
    if not cfg.get("SMTP_HOST"):
        missing.append("SMTP_HOST")
    if not sender:
        missing.append("SMTP_FROM or SMTP_USERNAME")
    if missing:
        raise ValueError("Missing email config: " + ", ".join(missing))


def send_report_email(cfg, paths, subject=None, smtp_factory=None):
    require_email_config(cfg)
    message = EmailMessage()
    sender = cfg.get("SMTP_FROM") or cfg.get("SMTP_USERNAME")
    message["From"] = sender
    message["To"] = cfg["email_receiver"]
    message["Subject"] = subject or "CNVD report files"
    message.set_content("Generated report files are attached.")

    for path in paths:
        ctype, _ = mimetypes.guess_type(path)
        maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
        with open(path, "rb") as f:
            message.add_attachment(
                f.read(),
                maintype=maintype,
                subtype=subtype,
                filename=os.path.basename(path),
            )

    port = int(cfg.get("SMTP_PORT") or 587)
    smtp_class = smtp_factory or (smtplib.SMTP_SSL if cfg.get("SMTP_USE_SSL") else smtplib.SMTP)
    with smtp_class(cfg["SMTP_HOST"], port, timeout=30) as smtp:
        if cfg.get("SMTP_USE_TLS") and not cfg.get("SMTP_USE_SSL"):
            smtp.starttls()
        username = cfg.get("SMTP_USERNAME")
        password = cfg.get("SMTP_PASSWORD")
        if username and password:
            try:
                smtp.login(username, password)
            except smtplib.SMTPNotSupportedError:
                pass
        smtp.send_message(message)
