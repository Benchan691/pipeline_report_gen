from pipeline.transfer import require_transfer_config, zimbra_send_email


def build_link_body(body, link_url):
    text = str(body or "Report link below.").rstrip()
    link_url = str(link_url or "").strip()
    if not link_url:
        raise ValueError("Missing share URL for email")
    return f"{text}\n\n{link_url}"


def require_email_config(cfg):
    receiver = str(cfg.get("email_receiver") or "").strip()
    missing = []
    if not receiver:
        missing.append("EMAIL_RECEIVER in .env")
    try:
        require_transfer_config(cfg)
    except ValueError as exc:
        missing.append(str(exc).replace("Missing transfer config: ", ""))
    if missing:
        raise ValueError("Missing email config: " + ", ".join(missing))


def send_report_email(cfg, share_url, subject=None):
    zimbra_send_email(
        cfg,
        cfg["email_receiver"],
        subject or str(cfg.get("email_title") or "漏洞報告文件").strip(),
        build_link_body(cfg.get("email_body"), share_url),
    )
