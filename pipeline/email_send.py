from report_email import SmtpConfig, load_email_config, require_smtp_config, send_link_email


def smtp_config_from_cfg(cfg):
    return SmtpConfig(
        host=str(cfg.get("zimbra_host") or "").strip(),
        port=int(cfg.get("zimbra_smtp_port") or 587),
        username=str(cfg.get("zimbra_email") or "").strip(),
        password=str(cfg.get("zimbra_password") or "").strip(),
        from_addr=str(cfg.get("zimbra_email") or "").strip(),
        use_tls=bool(cfg.get("zimbra_smtp_use_tls", True)),
        use_ssl=bool(cfg.get("zimbra_smtp_use_ssl", False)),
    )


def require_email_config(cfg):
    receiver = str(cfg.get("email_receiver") or "").strip()
    smtp = smtp_config_from_cfg(cfg)
    missing = []
    if not receiver:
        missing.append("EMAIL_RECEIVER in .env")
    if not smtp.host:
        missing.append("ZIMBRA_HOST in .env")
    if not smtp.username:
        missing.append("ZIMBRA_EMAIL in .env")
    if not smtp.password:
        missing.append("ZIMBRA_PASSWORD in .env")
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
