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


def useful_ref(doc, raw):
    links = raw.get("reference_links") or []
    for link in [doc.get("source", {}).get("detail_url"), *links]:
        if link and "login" not in link and "regist" not in link:
            return link
    return "-"


def candidate_from_doc(doc):
    raw = doc.get("details", {}).get("cnvd", {})
    cnvd_id = norm_cnvd(raw.get("cnvd_id") or doc.get("code"))
    cve = norm_cve((raw.get("cve_ids") or doc.get("cve_codes") or [None])[0])
    products = raw.get("affected_products") or []
    return {
        "candidate_id": cnvd_id,
        "source": "cnvd",
        "cnvd_id": cnvd_id,
        "cve_id": cve,
        "search_id": cve or cnvd_id,
        "title": raw.get("title") or doc.get("title") or cnvd_id,
        "severity": doc.get("severity") or raw.get("severity"),
        "summary": raw.get("description") or "",
        "solution": raw.get("solution") or "",
        "affected_products": products,
        "references": [useful_ref(doc, raw)],
        "doc": doc,
    }


def candidate_from_cnnvd_doc(doc):
    raw = doc.get("details", {}).get("cnnvd", {})
    cnnvd_id = norm_cnnvd(raw.get("cnnvdId") or doc.get("code"))
    cve = norm_cve(raw.get("cveId") or (doc.get("cve_codes") or [None])[0])
    products = [p for p in [raw.get("vendorName"), raw.get("productName")] if p]
    return {
        "candidate_id": cnnvd_id,
        "source": "cnnvd",
        "cnvd_id": cnnvd_id,
        "cve_id": cve,
        "search_id": cve or cnnvd_id,
        "title": raw.get("vulName") or doc.get("title") or cnnvd_id,
        "severity": doc.get("severity") or raw.get("vulLevel") or doc.get("status"),
        "summary": raw.get("vulDesc") or raw.get("vulDetail") or "",
        "solution": raw.get("fixStatus") or "",
        "affected_products": products,
        "references": [useful_ref(doc, raw)],
        "doc": doc,
    }


def docs_to_candidates(docs):
    by_id = {}
    ordered_ids = []
    for doc in docs:
        raw = doc.get("details", {}).get("cnvd", {})
        cnvd_id = norm_cnvd(raw.get("cnvd_id") or doc.get("code"))
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
        raw = doc.get("details", {}).get("cnnvd", {})
        vuln_id = norm_cnnvd(raw.get("cnnvdId") or doc.get("code"))
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
    log.info("Querying MongoDB (%s.cnvd) scraped within last %d day(s)", DB, days)
    script = """
const cutoff = new Date(Date.now() - __DAYS__ * 24 * 60 * 60 * 1000).toISOString();
const docs = db.getSiblingDB("__DB__").cnvd.find({
  scraped_at: {$gte: cutoff}
}).sort({scraped_at: -1, code: -1}).toArray();
print(JSON.stringify(docs));
""".replace("__DAYS__", str(days)).replace("__DB__", DB)
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
    script = """
const ids = __IDS__;
const codes = __CODES__;
const mongoIds = __MONGO_IDS__;
const docs = db.getSiblingDB("__DB__").cnvd.find({
  $or: [
    {_id: {$in: mongoIds}},
    {code: {$in: codes}},
    {"details.cnvd.cnvd_id": {$in: ids}}
  ]
}).toArray();
print(JSON.stringify(docs));
""".replace("__IDS__", json.dumps(cnvd_ids)).replace("__CODES__", json.dumps(codes)).replace("__MONGO_IDS__", json.dumps(mongo_ids)).replace("__DB__", DB)
    docs = run_mongo(script)
    by_id = {}
    for doc in docs:
        raw = doc.get("details", {}).get("cnvd", {})
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
    script = """
const ids = __IDS__;
const codes = __CODES__;
const mongoIds = __MONGO_IDS__;
const docs = db.getSiblingDB("__DB__").cnnvd.find({
  $or: [
    {_id: {$in: mongoIds}},
    {code: {$in: codes}},
    {"details.cnnvd.cnnvdId": {$in: ids}}
  ]
}).toArray();
print(JSON.stringify(docs));
""".replace("__IDS__", json.dumps(cnnvd_ids)).replace("__CODES__", json.dumps(codes)).replace("__MONGO_IDS__", json.dumps(mongo_ids)).replace("__DB__", DB)
    docs = run_mongo(script)
    by_id = {}
    for doc in docs:
        raw = doc.get("details", {}).get("cnnvd", {})
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
