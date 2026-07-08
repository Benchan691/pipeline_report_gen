from report_email import SmtpConfig, load_email_config, require_smtp_config, send_link_email


def smtp_config_from_cfg(cfg):
    return SmtpConfig(
        host=str(cfg.get("SMTP_HOST") or "").strip(),
        port=int(cfg.get("SMTP_PORT") or 587),
        username=str(cfg.get("SMTP_USERNAME") or "").strip(),
        password=str(cfg.get("SMTP_PASSWORD") or "").strip(),
        from_addr=str(cfg.get("SMTP_FROM") or cfg.get("SMTP_USERNAME") or "").strip(),
        use_tls=bool(cfg.get("SMTP_USE_TLS", True)),
        use_ssl=bool(cfg.get("SMTP_USE_SSL", False)),
    )


def require_email_config(cfg):
    receiver = str(cfg.get("email_receiver") or "").strip()
    smtp = smtp_config_from_cfg(cfg)
    sender = smtp.from_addr or smtp.username
    missing = []
    if not receiver:
        missing.append("EMAIL_RECEIVER in .env")
    if not smtp.host:
        missing.append("SMTP_HOST in .env")
    if not sender:
        missing.append("SMTP_FROM or SMTP_USERNAME in .env")
    if missing:
        raise ValueError("Missing email config: " + ", ".join(missing))


def send_report_email(cfg, share_url, subject=None, smtp_factory=None):
    email_cfg = load_email_config()
    send_link_email(
        smtp_config_from_cfg(cfg),
        to=cfg["email_receiver"],
        subject=subject or email_cfg.email_title,
        body=email_cfg.email_body,
        link_url=share_url,
        smtp_factory=smtp_factory,
    )
