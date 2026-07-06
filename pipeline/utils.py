import hashlib
import json


def short_url(url, max_len=60):
    text = (url or "").strip()
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def norm_cnvd(value):
    value = str(value).strip()
    if value.lower().startswith("cnvd:"):
        value = value.split(":", 1)[1]
    if not value.upper().startswith("CNVD-"):
        value = "CNVD-" + value
    return value.upper()


def norm_cnnvd(value):
    value = str(value).strip()
    if value.lower().startswith("cnnvd:"):
        value = value.split(":", 1)[1]
    if not value.upper().startswith("CNNVD-"):
        value = "CNNVD-" + value
    return value.upper()


def norm_cve(value):
    if not value:
        return None
    value = str(value).strip().upper()
    if value.startswith("CVE:"):
        value = value.split(":", 1)[1]
    if not value.startswith("CVE-"):
        value = "CVE-" + value
    return value


def val(value, default="-"):
    if value is None:
        return default
    if isinstance(value, list):
        return "\n".join(str(v) for v in value if v) or default
    value = str(value).strip()
    return value or default


def one_line(value):
    return val(value).splitlines()[0]


def content_hash(*parts):
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def unique(values):
    out, seen = [], set()
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out
