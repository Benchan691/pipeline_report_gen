"""Normalize scraper payloads without restricting the providers accepted by news."""

import re
from datetime import datetime, timezone

from pipeline.utils import norm_cnvd, norm_cnnvd, unique


def doc_provider(doc, default=None):
    source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    value = source.get("provider") or default or ""
    return value.strip().lower() if isinstance(value, str) else ""


def provider_details(doc, source=None):
    details = doc.get("details") if isinstance(doc.get("details"), dict) else {}
    source = doc_provider(doc, source)
    return details[source] if isinstance(details.get(source), dict) else details


def text(value):
    """Flatten text containers, keeping their values rather than Python reprs."""
    if isinstance(value, dict):
        if "value" in value:
            return text(value["value"])
        return "\n".join(part for item in value.values() if (part := text(item)))
    if isinstance(value, (list, tuple)):
        return "\n".join(part for item in value if (part := text(item)))
    return str(value).strip() if value is not None and not isinstance(value, bool) else ""


def first_text(*values):
    return next((part for value in values if (part := text(value))), "")


def names(value):
    if isinstance(value, (list, tuple)):
        return unique(name for item in value for name in names(item))
    if isinstance(value, dict):
        return names(value.get("name") or value.get("product") or value.get("packageName") or value.get("vendor") or value.get("value"))
    return [text(value)] if text(value) else []


def doc_record_id(doc, provider=None):
    record_id = doc.get("_id")
    if record_id not in (None, ""):
        return str(record_id)
    provider = doc_provider(doc, provider)
    raw = provider_details(doc, provider)
    code = first_text(doc.get("code"), raw.get("cnvd_id"), raw.get("cnnvdId"), raw.get("ghsa_id"))
    # Legacy CNVD/CNNVD documents did not always carry _id in exported payloads.
    if provider == "cnvd":
        code = norm_cnvd(code).removeprefix("CNVD-") if code else ""
    elif provider == "cnnvd":
        code = norm_cnnvd(code).removeprefix("CNNVD-") if code else ""
    return f"{provider}:{code}" if provider in ("cnvd", "cnnvd") and code else ""


def doc_display_id(doc, provider=None):
    provider = doc_provider(doc, provider)
    raw = provider_details(doc, provider)
    record_id = doc_record_id(doc, provider)
    code = record_id.split(":", 1)[1] if record_id.lower().startswith(f"{provider}:") else first_text(doc.get("code"), record_id)
    if provider == "cnvd":
        return norm_cnvd(code or raw.get("cnvd_id"))
    if provider == "cnnvd":
        return norm_cnnvd(code or raw.get("cnnvdId"))
    if provider in ("cve", "nvd", "msrc"):
        return code.upper() if code.upper().startswith("CVE-") else f"CVE-{code}" if code else ""
    if provider == "avd":
        return code.upper() if code.upper().startswith("AVD-") else f"AVD-{code}" if code else ""
    if provider == "github_advisory":
        return first_text(raw.get("ghsa_id")) or (code if code.upper().startswith("GHSA-") else f"GHSA-{code}" if code else "")
    if provider == "govcert":
        return first_text(raw.get("alert_code"), code)
    if provider == "hpe":
        return first_text(raw.get("bulletin_id"), code)
    return code


def timestamp_text(value):
    if isinstance(value, dict) and "$date" in value:
        value = value["$date"]
        if isinstance(value, dict) and "$numberLong" in value:
            try:
                return datetime.fromtimestamp(int(value["$numberLong"]) / 1000, timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                return ""
    return text(value)


def doc_published_text(doc, source=None):
    raw = provider_details(doc, source)
    return next((part for value in (
        doc.get("published_at"), raw.get("published_date"), raw.get("publishDate"),
        raw.get("publishTime"), doc.get("disclosure_date"), doc.get("published_time"),
        doc.get("observed_at"), doc.get("scraped_at"),
    ) if (part := timestamp_text(value))), "")


def doc_cve_ids(doc, raw=None):
    raw = raw if raw is not None else provider_details(doc)
    values = [doc.get(key) for key in ("cve_ids", "cve_codes", "cve_id", "cveId", "cveCode")]
    values.extend(raw.get(key) for key in ("cve_ids", "cve_id", "cveId", "cveCode"))
    values.extend(item.get("value") for item in raw.get("identifiers") or [] if isinstance(item, dict) and text(item.get("type")).upper() == "CVE")
    values.extend(item.get("cveId") for item in raw.get("vul") or [] if isinstance(item, dict))
    description = raw.get("description")
    if isinstance(description, dict):
        for key in ("vulnerability_information", "threat_assessment"):
            item = description.get(key)
            if isinstance(item, dict):
                values.append(item.get("cve_id"))
    if doc_provider(doc) in ("cve", "msrc", "nvd"):
        values.append(doc_display_id(doc))
    out = []
    for value in values:
        for part in names(value):
            part = part.upper().replace("CVE:", "CVE-")
            if re.fullmatch(r"\d{4}-\d+", part):
                part = "CVE-" + part
            out.extend(re.findall(r"\bCVE-\d{4}-\d+\b", part))
    return unique(out)


def norm_severity(value):
    part = re.split(r"[\s(（]", text(value), maxsplit=1)[0].lower()
    mapping = {
        "critical": "Critical", "critical-risk": "Critical", "超危": "Critical", "严重": "Critical",
        "high": "High", "高": "High", "高危": "High", "high-risk": "High", "important": "High",
        "medium": "Medium", "中": "Medium", "中危": "Medium", "medium-risk": "Medium", "moderate": "Medium",
        "low": "Low", "低": "Low", "低危": "Low", "low-risk": "Low",
        "none": "None",
    }
    return mapping.get(part, text(value))


def _cvss_scores(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("base_score", "baseScore", "score", "cvss_3_1_score"):
                try:
                    score = float(item)
                    if 0 <= score <= 10:
                        yield score
                except (ValueError, TypeError):
                    pass
            elif isinstance(item, (dict, list)):
                yield from _cvss_scores(item)
    elif isinstance(value, list):
        for item in value:
            yield from _cvss_scores(item)


def doc_severity(doc, raw=None):
    raw = raw if raw is not None else provider_details(doc)
    value = first_text(doc.get("severity"), raw.get("severity"), raw.get("vulLevel"), raw.get("hazardLevel"))
    if value:
        return norm_severity(value)
    scores = list(_cvss_scores({key: raw.get(key) for key in (
        "base_score", "baseScore", "score", "metrics", "cvss", "cvss_severities", "cvss_entries", "description",
    )}))
    if scores:
        score = max(scores)
        return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "None"
    status = norm_severity(doc.get("status"))
    return status if status in ("Critical", "High", "Medium", "Low", "None") else None


def cpe_names(value):
    value = text(value)
    parts = re.split(r"(?<!\\):", value)
    start = 3 if value.startswith("cpe:2.3:") else 2 if value.startswith("cpe:/") else None
    if start is None or len(parts) <= start + 1:
        return [], []
    vendor, product = (re.sub(r"\\(.)", r"\1", part).replace("_", " ") for part in parts[start:start + 2])
    return ([product] if product not in ("*", "-") else []), ([vendor] if vendor not in ("*", "-") else [])


def _vulnerable_cpes(value):
    if isinstance(value, dict):
        if value.get("vulnerable") is True:
            yield value.get("criteria") or value.get("cpe23Uri")
        for item in value.values():
            if isinstance(item, (dict, list)):
                yield from _vulnerable_cpes(item)
    elif isinstance(value, list):
        for item in value:
            yield from _vulnerable_cpes(item)


def _affected_item(item):
    if not isinstance(item, dict):
        return True
    statuses = [text(version.get("status")).lower() for version in item.get("versions") or [] if isinstance(version, dict)]
    default = text(item.get("defaultStatus")).lower()
    return default == "affected" or "affected" in statuses or (not statuses and default != "unaffected")


def reference_links(doc, raw):
    source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    values = [source.get("detail_url"), raw.get("detail_url"), raw.get("html_url"), raw.get("doc_display_url")]
    values.extend(raw.get(key) for key in (
        "reference_links", "references", "referUrl", "related_links", "officialPatchLink",
        "more_information_links", "solution_links", "patch_installation_url", "remediations",
    ))
    description = raw.get("description")
    if isinstance(description, dict):
        values.append(description.get("references"))
    values.append(source.get("url"))
    links = []
    for value in values:
        links.extend(re.findall(r"(?:https?|ftp)://[^\s<>\[\]{}\"']+", text(value)))
    return unique(link.rstrip(".,;)") for link in links if "login" not in link.lower() and "regist" not in link.lower())


def news_fields(doc, source=None):
    """Shared fields for candidate intake, keyword matching and AI confirmation.

    Only explicit affected product fields enter keyword matching. Descriptions
    remain evidence for confirmation, so incidental language names are not hits.
    """
    provider = doc_provider(doc, source)
    raw = {**doc, **provider_details(doc, provider)}
    products, vendors = [], []
    for container in (doc, raw):
        for key in ("affected_products", "products", "product", "product_name", "product_names", "productName", "affectedProduct", "affected_systems", "systems_affected", "affected_software", "products_affected"):
            products.extend(names(container.get(key)))
        for key in ("vendor", "vendors", "vendor_name", "vendor_names", "vendorName", "affectedVendor"):
            vendors.extend(names(container.get(key)))
    summary = first_text(raw.get("description"), raw.get("vulDesc"), raw.get("vulDetail"), raw.get("productDesc"), raw.get("summary"), raw.get("intro"), raw.get("digest"))
    solution = first_text(raw.get("solution"), raw.get("solutions"), raw.get("fixStatus"), raw.get("patch"), raw.get("recommendation"), raw.get("recommendations"), raw.get("resolution"), raw.get("remediation"))
    descriptions = raw.get("descriptions") or []
    summary = summary or first_text([item for item in descriptions if isinstance(item, dict) and item.get("lang") == "en"], descriptions)
    for item in raw.get("affected") or []:
        if not _affected_item(item):
            continue
        if isinstance(item, dict):
            products.extend(names(item.get("product")))
            products.extend(names(item.get("packageName")))
            vendors.extend(names(item.get("vendor")))
            for cpe in names(item.get("cpes")):
                cpe_products, cpe_vendors = cpe_names(cpe)
                products.extend(cpe_products)
                vendors.extend(cpe_vendors)
    cpes = [product for product in products if product.startswith("cpe:")]
    products = [product for product in products if not product.startswith("cpe:")]
    for cpe in [*cpes, *_vulnerable_cpes(raw.get("configurations"))]:
        cpe_products, cpe_vendors = cpe_names(cpe)
        products.extend(cpe_products)
        vendors.extend(cpe_vendors)
    if provider == "github_advisory":
        fixes = []
        for item in raw.get("vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            package = names(item.get("package"))
            products.extend(package)
            fixed = text(item.get("first_patched_version"))
            if fixed and package:
                fixes.append(f"{package[0]}: first patched version {fixed}")
        solution = solution or text(fixes)
    elif provider == "hpe":
        if not products:
            products.extend(names(raw.get("supported_versions") or raw.get("supported_software_versions")))
        solution = text([solution, raw.get("workaround")])
    elif provider == "msrc":
        for item in raw.get("product_statuses") or []:
            if isinstance(item, dict) and text(item.get("type")).lower().replace("_", "") in ("1", "3", "4", "knownaffected", "firstaffected", "lastaffected"):
                products.extend(names(item.get("product_names")))
        solution = solution or text([text([item.get("description"), item.get("url")]) for item in raw.get("remediations") or [] if isinstance(item, dict)])
    elif provider == "qianxin" and isinstance(raw.get("description"), dict):
        description = raw["description"]
        info = description.get("vulnerability_information") or {}
        if isinstance(info, dict):
            products.extend(names(info.get("product")))
            products.extend(names(info.get("affected_versions")))
            vendors.extend(names(info.get("vendor")))
            summary = first_text(info.get("summary"), info.get("vulnerability_description"), description.get("security_advisory"), raw.get("digest"))
        solution = solution or text(description.get("recommendations"))
    elif provider == "zimbra":
        products.append("Zimbra")
        summary = summary or text(raw.get("security_fixes"))
        solution = solution or text(raw.get("patch_installation_url"))
    return {
        "title": first_text(doc.get("title"), raw.get("title"), raw.get("vulName"), raw.get("summary"), doc_display_id(doc, provider)),
        "affected_products": unique(products),
        "vendors": unique(vendors),
        "severity": doc_severity(doc, raw),
        "summary": summary,
        "solution": solution,
        "references": reference_links(doc, raw),
    }
