"""Re-export the report_email client for import-based use."""

from report_email import EmailConfig, SmtpConfig, build_link_body, load_email_config, require_smtp_config, send_link_email

__all__ = ["EmailConfig", "SmtpConfig", "build_link_body", "load_email_config", "require_smtp_config", "send_link_email"]
