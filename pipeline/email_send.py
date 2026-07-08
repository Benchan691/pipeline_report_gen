from report_email import build_link_body, load_email_config

from pipeline.transfer import require_transfer_config, zimbra_send_email


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
    email_cfg = load_email_config()
    zimbra_send_email(
        cfg,
        cfg["email_receiver"],
        subject or email_cfg.email_title,
        build_link_body(email_cfg.email_body, share_url),
    )
