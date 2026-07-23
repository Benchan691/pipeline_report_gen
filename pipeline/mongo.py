import json
import logging
import shutil
import subprocess
import sys

from pipeline.constants import DB
from pipeline.utils import norm_cnvd, norm_cnnvd, norm_cve

log = logging.getLogger(__name__)


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
    for value in (raw.get("reference_links"), raw.get("referUrl"), raw.get("related_links")):
        if isinstance(value, list):
            links.extend(value)
        elif value:
            links.append(value)
    for link in [doc.get("source", {}).get("detail_url"), *links]:
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


def candidate_from_doc(doc):
    raw = provider_details(doc, "cnvd")
    cnvd_id = norm_cnvd(doc.get("code") or raw.get("cnvd_id") or str(doc.get("_id", "")).split(":", 1)[-1])
    cve_ids = doc_cve_ids(doc, raw)
    products = raw.get("affected_products") or []
    if isinstance(products, str):
        products = [products] if products.strip() else []
    return {
        "candidate_id": cnvd_id,
        "source": "cnvd",
        "cnvd_id": cnvd_id,
        "cve_id": cve_ids[0] if cve_ids else None,
        "search_id": (cve_ids[0] if cve_ids else None) or cnvd_id,
        "title": doc.get("title") or raw.get("title") or cnvd_id,
        "severity": doc.get("severity") or raw.get("severity"),
        "summary": raw.get("description") or "",
        "solution": raw.get("solution") or "",
        "affected_products": products,
        "references": [useful_ref(doc, raw)],
        "doc": doc,
    }


def candidate_from_cnnvd_doc(doc):
    raw = provider_details(doc, "cnnvd")
    cnnvd_id = norm_cnnvd(doc.get("code") or raw.get("cnnvdId") or str(doc.get("_id", "")).split(":", 1)[-1])
    cve_ids = doc_cve_ids(doc, raw)
    products = [
        p for p in [
            raw.get("vendorName"),
            raw.get("productName"),
            raw.get("affectedVendor"),
            raw.get("affectedProduct"),
        ] if p
    ]
    return {
        "candidate_id": cnnvd_id,
        "source": "cnnvd",
        "cnvd_id": cnnvd_id,
        "cve_id": cve_ids[0] if cve_ids else None,
        "search_id": (cve_ids[0] if cve_ids else None) or cnnvd_id,
        "title": doc.get("title") or raw.get("vulName") or cnnvd_id,
        "severity": doc.get("severity") or raw.get("vulLevel") or raw.get("hazardLevel") or doc.get("status"),
        "summary": raw.get("vulDesc") or raw.get("vulDetail") or raw.get("productDesc") or "",
        "solution": raw.get("fixStatus") or raw.get("patch") or "",
        "affected_products": products,
        "references": [useful_ref(doc, raw)],
        "doc": doc,
    }


def docs_to_candidates(docs):
    by_id = {}
    ordered_ids = []
    for doc in docs:
        raw = provider_details(doc, "cnvd")
        cnvd_id = norm_cnvd(doc.get("code") or raw.get("cnvd_id") or str(doc.get("_id", "")).split(":", 1)[-1])
        if cnvd_id not in by_id:
            by_id[cnvd_id] = doc
            ordered_ids.append(cnvd_id)
    candidates = [candidate_from_doc(by_id[i]) for i in ordered_ids]
    for c in candidates:
        cve = c.get("cve_id") or "no CVE"
        log.info("  loaded %s (%s): %s", c["cnvd_id"], cve, c["title"][:80])
    return candidates


def docs_to_cnnvd_candidates(docs):
    by_id = {}
    ordered_ids = []
    for doc in docs:
        raw = provider_details(doc, "cnnvd")
        vuln_id = norm_cnnvd(doc.get("code") or raw.get("cnnvdId") or str(doc.get("_id", "")).split(":", 1)[-1])
        if vuln_id not in by_id:
            by_id[vuln_id] = doc
            ordered_ids.append(vuln_id)
    candidates = [candidate_from_cnnvd_doc(by_id[i]) for i in ordered_ids]
    for c in candidates:
        cve = c.get("cve_id") or "no CVE"
        log.info("  loaded %s (%s): %s", c["cnvd_id"], cve, c["title"][:80])
    return candidates


def query_cnvd_by_scrape_days(days):
    days = int(days)
    if days < 1:
        sys.exit("scrape_days must be >= 1")
    log.info("Querying MongoDB (%s.cnvd) observed within last %d day(s)", DB, days)
    script = (_serialize_dates_js() + """
const cutoff = new Date(Date.now() - __DAYS__ * 24 * 60 * 60 * 1000);
const cutoffIso = cutoff.toISOString();
const docs = db.getSiblingDB("__DB__").cnvd.find({
  $or: [
    {observed_at: {$gte: cutoff}},
    {scraped_at: {$gte: cutoffIso}}
  ]
}).sort({observed_at: -1, scraped_at: -1, code: -1}).toArray();
print(JSON.stringify(serializeDocs(docs)));
""").replace("__DAYS__", str(days)).replace("__DB__", DB)
    docs = run_mongo(script)
    if not docs:
        log.info("  found 0 record(s) in scrape window")
        return []
    log.info("  found %d record(s) in scrape window", len(docs))
    return docs_to_candidates(docs)


def query_cnvd(ids):
    cnvd_ids = [norm_cnvd(i) for i in ids]
    log.info("Querying MongoDB (%s.cnvd) for %d ID(s)", DB, len(cnvd_ids))
    codes = [i.removeprefix("CNVD-") for i in cnvd_ids]
    mongo_ids = ["cnvd:" + c for c in codes]
    script = (_serialize_dates_js() + """
const ids = __IDS__;
const codes = __CODES__;
const mongoIds = __MONGO_IDS__;
const docs = db.getSiblingDB("__DB__").cnvd.find({
  $or: [
    {_id: {$in: mongoIds}},
    {code: {$in: codes}},
    {"details.cnvd_id": {$in: ids}},
    {"details.cnvd.cnvd_id": {$in: ids}}
  ]
}).toArray();
print(JSON.stringify(serializeDocs(docs)));
""").replace("__IDS__", json.dumps(cnvd_ids)).replace("__CODES__", json.dumps(codes)).replace("__MONGO_IDS__", json.dumps(mongo_ids)).replace("__DB__", DB)
    docs = run_mongo(script)
    by_id = {}
    for doc in docs:
        raw = provider_details(doc, "cnvd")
        keys = [
            raw.get("cnvd_id"),
            doc.get("code"),
            str(doc.get("_id", "")).split(":", 1)[-1],
        ]
        for key in keys:
            if key:
                by_id[norm_cnvd(key)] = doc
    missing = [i for i in cnvd_ids if i not in by_id]
    if missing:
        sys.exit("Not found in vulnerabilities.cnvd: " + ", ".join(missing))
    return docs_to_candidates([by_id[i] for i in cnvd_ids])


def query_cnnvd(ids):
    cnnvd_ids = [norm_cnnvd(i) for i in ids]
    log.info("Querying MongoDB (%s.cnnvd) for %d ID(s)", DB, len(cnnvd_ids))
    codes = [i.removeprefix("CNNVD-") for i in cnnvd_ids]
    mongo_ids = ["cnnvd:" + c for c in codes]
    script = (_serialize_dates_js() + """
const ids = __IDS__;
const codes = __CODES__;
const mongoIds = __MONGO_IDS__;
const docs = db.getSiblingDB("__DB__").cnnvd.find({
  $or: [
    {_id: {$in: mongoIds}},
    {code: {$in: codes}},
    {"details.cnnvdId": {$in: ids}},
    {"details.cnnvd.cnnvdId": {$in: ids}}
  ]
}).toArray();
print(JSON.stringify(serializeDocs(docs)));
""").replace("__IDS__", json.dumps(cnnvd_ids)).replace("__CODES__", json.dumps(codes)).replace("__MONGO_IDS__", json.dumps(mongo_ids)).replace("__DB__", DB)
    docs = run_mongo(script)
    by_id = {}
    for doc in docs:
        raw = provider_details(doc, "cnnvd")
        keys = [
            raw.get("cnnvdId"),
            doc.get("code"),
            str(doc.get("_id", "")).split(":", 1)[-1],
        ]
        for key in keys:
            if key:
                by_id[norm_cnnvd(key)] = doc
    missing = [i for i in cnnvd_ids if i not in by_id]
    if missing:
        sys.exit("Not found in vulnerabilities.cnnvd: " + ", ".join(missing))
    return docs_to_cnnvd_candidates([by_id[i] for i in cnnvd_ids])


def candidates_from_payload(payload):
    matches = payload.get("matches") or []
    if not matches:
        return []
    by_source = {"cnvd": [], "cnnvd": []}
    for match in matches:
        source = match.get("source")
        if source in by_source:
            by_source[source].append(match["id"])
    candidates = {}
    for candidate in query_cnvd(by_source["cnvd"]):
        candidates[("cnvd", candidate["cnvd_id"])] = candidate
    for candidate in query_cnnvd(by_source["cnnvd"]):
        candidates[("cnnvd", candidate["cnvd_id"])] = candidate
    ordered = []
    for match in matches:
        key = (match.get("source"), match.get("id"))
        if key in candidates:
            candidate = candidates[key]
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
