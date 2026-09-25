import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from pipeline.constants import DB
from pipeline.utils import norm_cnvd, norm_cnnvd, norm_cve

log = logging.getLogger(__name__)
SUPPORTED_PROVIDERS = ("cnvd", "cnnvd")


def run_mongo(script):
    mongosh = shutil.which("mongosh")
    if not mongosh:
        sys.exit("mongosh not found. Install MongoDB Shell or add it to PATH.")
    res = subprocess.run(
        [mongosh, "--quiet", "--host", "localhost", "--port", "27017", "--eval", script],
        text=True,
        capture_output=True,
    )
    if res.returncode:
        sys.exit(res.stderr.strip() or res.stdout.strip() or "Mongo query failed")
    return json.loads(res.stdout.strip() or "[]")


def provider_details(doc, source=None):
    """Return provider payload for schema v2 (flat details) or legacy v1 wrapper."""
    details = doc.get("details") if isinstance(doc.get("details"), dict) else {}
    if source and isinstance(details.get(source), dict):
        return details[source]
    return details


def doc_provider(doc, default=None):
    source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    provider = source.get("provider") or default or ""
    return str(provider).strip().lower()


def doc_record_id(doc, provider=None):
    record_id = doc.get("_id")
    if record_id not in (None, ""):
        return str(record_id)
    provider = doc_provider(doc, provider)
    raw = provider_details(doc, provider)
    code = doc.get("code") or raw.get("cnvd_id") or raw.get("cnnvdId")
    if code and provider in SUPPORTED_PROVIDERS:
        display_id = norm_cnvd(code) if provider == "cnvd" else norm_cnnvd(code)
        prefix = "CNVD-" if provider == "cnvd" else "CNNVD-"
        return f"{provider}:{display_id.removeprefix(prefix)}"
    return ""


def doc_display_id(doc, provider=None):
    provider = doc_provider(doc, provider)
    if provider not in SUPPORTED_PROVIDERS:
        return ""
    record_id = doc_record_id(doc, provider)
    prefix = f"{provider}:"
    if record_id.lower().startswith(prefix):
        code = record_id.split(":", 1)[1]
    else:
        raw = provider_details(doc, provider)
        code = doc.get("code") or raw.get("cnvd_id") or raw.get("cnnvdId") or record_id
    return norm_cnvd(code) if provider == "cnvd" else norm_cnnvd(code)


def timestamp_text(value):
    if value in (None, ""):
        return ""
    if isinstance(value, dict) and "$date" in value:
        value = value["$date"]
        if isinstance(value, dict) and "$numberLong" in value:
            try:
                from datetime import datetime, timezone

                ms = int(value["$numberLong"])
                return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                return ""
    return str(value).strip()


def doc_cve_ids(doc, raw=None):
    raw = raw if raw is not None else provider_details(doc)
    values = []
    for field in ("cve_ids", "cve_codes"):
        value = doc.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    for field in ("cve_ids", "cve_id", "cveId", "cveCode"):
        value = raw.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    out = []
    for value in values:
        cve = norm_cve(value)
        if cve and cve not in out:
            out.append(cve)
    return out


def doc_published_text(doc, source=None):
    raw = provider_details(doc, source)
    for value in (
        doc.get("published_at"),
        raw.get("published_date"),
        raw.get("publishDate"),
        raw.get("publishTime"),
        doc.get("disclosure_date"),
        doc.get("published_time"),
        doc.get("observed_at"),
        doc.get("scraped_at"),
    ):
        text = timestamp_text(value)
        if text:
            return text
    return ""


def useful_ref(doc, raw):
    links = []
    for value in (
        raw.get("reference_links"),
        raw.get("referUrl"),
        raw.get("related_links"),
        raw.get("officialPatchLink"),
    ):
        if isinstance(value, list):
            links.extend(value)
        elif value:
            links.append(value)
    source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    for link in [source.get("detail_url"), *links]:
        if link and "login" not in str(link) and "regist" not in str(link):
            return link
    return "-"


def _serialize_dates_js():
    return """
function serializeDocs(docs) {
  return docs.map(doc => {
    for (const key of Object.keys(doc)) {
      if (doc[key] instanceof Date) doc[key] = doc[key].toISOString();
    }
    return doc;
  });
}
"""


def candidate_from_news_doc(doc, default_provider=None):
    provider = doc_provider(doc, default_provider)
    if provider not in SUPPORTED_PROVIDERS:
        return None
    raw = provider_details(doc, provider)
    record_id = doc_record_id(doc, provider)
    display_id = doc_display_id(doc, provider)
    cve_ids = doc_cve_ids(doc, raw)
    if provider == "cnvd":
        products = raw.get("affected_products") or []
        if isinstance(products, str):
            products = [products] if products.strip() else []
        title = doc.get("title") or raw.get("title") or display_id
        severity = doc.get("severity") or raw.get("severity") or doc.get("status")
        summary = raw.get("description") or ""
        solution = raw.get("solution") or ""
    else:
        products = [
            product for product in (
                raw.get("vendorName"),
                raw.get("productName"),
                raw.get("affectedVendor"),
                raw.get("affectedProduct"),
            ) if product
        ]
        title = doc.get("title") or raw.get("vulName") or display_id
        severity = doc.get("severity") or raw.get("vulLevel") or raw.get("hazardLevel") or doc.get("status")
        summary = raw.get("vulDesc") or raw.get("vulDetail") or raw.get("productDesc") or ""
        solution = raw.get("fixStatus") or raw.get("patch") or raw.get("solution") or ""
    return {
        "candidate_id": record_id or display_id,
        "record_id": record_id,
        "source": provider,
        "cnvd_id": display_id,
        "cve_id": cve_ids[0] if cve_ids else None,
        "search_id": (cve_ids[0] if cve_ids else None) or display_id,
        "title": title,
        "severity": severity,
        "summary": summary,
        "solution": solution,
        "affected_products": products,
        "references": [useful_ref(doc, raw)],
        "doc": doc,
    }


def candidate_from_doc(doc):
    return candidate_from_news_doc(doc, "cnvd")


def candidate_from_cnnvd_doc(doc):
    return candidate_from_news_doc(doc, "cnnvd")


def docs_to_candidates(docs):
    candidates = []
    seen = set()
    for doc in docs:
        candidate = candidate_from_news_doc(doc)
        if not candidate:
            provider = doc_provider(doc)
            log.debug("Skipping unsupported news provider %r", provider)
            continue
        record_id = candidate["record_id"] or candidate["cnvd_id"]
        if record_id in seen:
            continue
        seen.add(record_id)
        candidates.append(candidate)
    for candidate in candidates:
        cve = candidate.get("cve_id") or "no CVE"
        log.info("  loaded %s (%s): %s", candidate["cnvd_id"], cve, candidate["title"][:80])
    return candidates


def docs_to_cnnvd_candidates(docs):
    candidates = [candidate for candidate in docs_to_candidates(docs) if candidate["source"] == "cnnvd"]
    return candidates


def query_news(providers, days=None, record_ids=None):
    if isinstance(providers, str):
        providers = (providers,)
    providers = sorted({str(provider).strip().lower() for provider in providers if str(provider).strip()})
    providers = [provider for provider in providers if provider in SUPPORTED_PROVIDERS]
    if not providers or (record_ids is not None and not record_ids):
        return []
    cutoff_ms = ""
    if days is not None:
        days = int(days)
        if days < 1:
            sys.exit("scrape_days must be >= 1")
        cutoff_ms = str(int((datetime.now(timezone.utc).timestamp() - days * 86400) * 1000))
    record_ids = [str(record_id) for record_id in (record_ids or [])]
    log.info(
        "Querying MongoDB (%s.news) providers=%s days=%s ids=%d",
        DB,
        ",".join(provider.upper() for provider in providers),
        days,
        len(record_ids),
    )
    script = (_serialize_dates_js() + """
const providers = __PROVIDERS__;
const recordIds = __RECORD_IDS__;
const cutoffMs = __CUTOFF_MS__;
const cutoff = cutoffMs === "" ? null : new Date(Number(cutoffMs));
const cutoffIso = cutoff ? cutoff.toISOString() : null;
const query = {"source.provider": {$in: providers}};
if (recordIds.length) query._id = {$in: recordIds};
if (cutoff) query.$or = [{observed_at: {$gte: cutoff}}, {scraped_at: {$gte: cutoffIso}}];
const docs = db.getSiblingDB("__DB__").news.find(query, {
  code: 1, title: 1, severity: 1, status: 1, cve_ids: 1, cve_codes: 1, details: 1, source: 1,
  published_at: 1, updated_at: 1, observed_at: 1, disclosure_date: 1, published_time: 1, scraped_at: 1
}).sort({observed_at: -1, scraped_at: -1, code: -1}).toArray();
print(JSON.stringify(serializeDocs(docs)));
""").replace("__PROVIDERS__", json.dumps(providers)).replace(
        "__RECORD_IDS__", json.dumps(record_ids),
    ).replace("__CUTOFF_MS__", json.dumps(cutoff_ms)).replace("__DB__", DB)
    return run_mongo(script)


def query_cnvd_by_scrape_days(days):
    docs = query_news(("cnvd",), days=days)
    log.info("  found %d CNVD record(s) in scrape window", len(docs))
    return docs_to_candidates(docs)


def query_cnvd(ids):
    cnvd_ids = [norm_cnvd(value) for value in ids]
    record_ids = [f"cnvd:{value.removeprefix('CNVD-')}" for value in cnvd_ids]
    docs = query_news(("cnvd",), record_ids=record_ids)
    by_record_id = {doc_record_id(doc, "cnvd"): doc for doc in docs}
    missing = [record_id for record_id in record_ids if record_id not in by_record_id]
    if missing:
        missing_ids = [cnvd_ids[record_ids.index(record_id)] for record_id in missing]
        sys.exit("Not found in vulnerabilities.news (source.provider=cnvd): " + ", ".join(missing_ids))
    return docs_to_candidates([by_record_id[record_id] for record_id in record_ids])


def query_cnnvd(ids):
    cnnvd_ids = [norm_cnnvd(value) for value in ids]
    record_ids = [f"cnnvd:{value.removeprefix('CNNVD-')}" for value in cnnvd_ids]
    docs = query_news(("cnnvd",), record_ids=record_ids)
    by_record_id = {doc_record_id(doc, "cnnvd"): doc for doc in docs}
    missing = [record_id for record_id in record_ids if record_id not in by_record_id]
    if missing:
        missing_ids = [cnnvd_ids[record_ids.index(record_id)] for record_id in missing]
        sys.exit("Not found in vulnerabilities.news (source.provider=cnnvd): " + ", ".join(missing_ids))
    return docs_to_candidates([by_record_id[record_id] for record_id in record_ids])


def record_id_from_match(match):
    record_id = match.get("record_id") or match.get("_id")
    if record_id:
        return str(record_id)
    provider = str(match.get("source") or match.get("provider") or "").strip().lower()
    identifier = str(match.get("id") or "").strip()
    if provider not in SUPPORTED_PROVIDERS or not identifier:
        return ""
    if identifier.lower().startswith(f"{provider}:"):
        return identifier
    if provider == "cnvd":
        display_id = norm_cnvd(identifier)
        return f"cnvd:{display_id.removeprefix('CNVD-')}"
    display_id = norm_cnnvd(identifier)
    return f"cnnvd:{display_id.removeprefix('CNNVD-')}"


def candidates_from_payload(payload):
    matches = payload.get("matches") or []
    if not matches:
        return []
    match_record_ids = [record_id_from_match(match) for match in matches]
    record_ids = list(dict.fromkeys(
        record_id for record_id in match_record_ids
        if record_id and record_id.split(":", 1)[0].lower() in SUPPORTED_PROVIDERS
    ))
    providers = sorted({record_id.split(":", 1)[0].lower() for record_id in record_ids})
    docs = query_news(providers, record_ids=record_ids)
    candidates = {
        candidate["record_id"]: candidate
        for candidate in docs_to_candidates(docs)
        if candidate.get("record_id")
    }
    ordered = []
    for match, record_id in zip(matches, match_record_ids):
        candidate = candidates.get(record_id)
        if not candidate:
            continue
        candidate["mark"] = match.get("mark")
        candidate["mark_reasons"] = match.get("mark_reasons") or []
        candidate["cluster_label"] = match.get("cluster_label") or match.get("matched_software") or ""
        candidate["matched_software"] = match.get("matched_software") or ""
        ordered.append(candidate)
    return ordered


def query_filtered_vulns(path):
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    candidates = candidates_from_payload(payload)
    if not candidates:
        sys.exit(f"No matches found in {path}; run main.py to refresh the shortlist.")
    return candidates
