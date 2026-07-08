# report_email

Import-only SMTP client for sending emails with a share link in the body.

**Requirements:** Python 3.9+

## Install

```bash
pip install -e /path/to/report_email
```

## Config

Edit `config.json` in this package for the default email title and body:

```json
{
  "email_title": "漏洞報告文件",
  "email_body": "各位好：\n本週漏洞報告連結如下，敬請查閱。\n..."
}
```

Load with `load_email_config()` or pass `subject` / `body` explicitly to `send_link_email()`.

## Quick start

```python
from report_email import SmtpConfig, send_link_email

smtp = SmtpConfig(
    host="smtp.example.com",
    port=587,
    username="sender@example.com",
    password="secret",
    from_addr="sender@example.com",
    use_tls=True,
    use_ssl=False,
)

send_link_email(
    smtp,
    to="receiver@example.com",
    subject="Weekly report",
    body="Report link below.",
    link_url="https://example.com/share/abc123",
)
```

## Public API

```python
from report_email import EmailConfig, SmtpConfig, build_link_body, load_email_config, require_smtp_config, send_link_email
```

### `SmtpConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | `str` | — | SMTP server hostname |
| `port` | `int` | `587` | SMTP server port |
| `username` | `str` | `""` | SMTP login username |
| `password` | `str` | `""` | SMTP login password |
| `from_addr` | `str` | `""` | Visible sender address (falls back to `username`) |
| `use_tls` | `bool` | `True` | Use STARTTLS |
| `use_ssl` | `bool` | `False` | Use SMTP SSL |

### `send_link_email(smtp, *, to, subject, body, link_url, smtp_factory=None)`

Send a plain-text email with `body`, a blank line, then `link_url`. Does not read `.env`; the caller supplies all configuration.
