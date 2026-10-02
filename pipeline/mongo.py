import logging
import sys
from datetime import datetime, timedelta, timezone

from pipeline.config import load_config
from pipeline.constants import DB
from pipeline.utils import norm_cnvd, norm_cnnvd
from pipeline.news_schema import (
    doc_cve_ids, doc_display_id, doc_provider, doc_published_text,
    doc_record_id, news_fields, provider_details, reference_links, timestamp_text,
)

log = logging.getLogger(__name__)


def _serialize_mongo_value(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {key: _serialize_mongo_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_mongo_value(item) for item in value]
    if value.__class__.__name__ == "ObjectId":
        return str(value)
    return value


def run_mongo(query, sort=None):
    try:
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError
    except ImportError:
        sys.exit("PyMongo is required for MongoDB access. Install dependencies with: python -m pip install -r requirements.txt")

    uri = str(load_config(email_only=True).get("mongo_uri") or "").strip()
    if not uri:
        sys.exit("MongoDB URI is missing. Set mongo_uri in config.json or MONGODB_URI in .env.")
    try:
        with MongoClient(uri, serverSelectionTimeoutMS=10000, tz_aware=True) as client:
            cursor = client[DB].news.find(query)
            if sort:
                cursor = cursor.sort(sort)
            return [_serialize_mongo_value(doc) for doc in cursor]
    except PyMongoError as exc:
        log.error("MongoDB query failed (%s). Check the configured URI and server availability.", type(exc).__name__)
        sys.exit("MongoDB query failed. Check mongo_uri in config.json or MONGODB_URI in .env, and confirm the server is reachable.")


def useful_ref(doc, raw):
    return next(iter(reference_links(doc, raw)), "-")


def candidate_from_news_doc(doc, default_provider=None):
    provider = doc_provider(doc, default_provider)
    if not provider:
        return None
    raw = provider_details(doc, provider)
    record_id = doc_record_id(doc, provider)
    if not record_id:
        return None
    display_id = doc_display_id(doc, provider)
    cve_ids = doc_cve_ids(doc, raw)
    fields = news_fields(doc, provider)
    return {
        "candidate_id": record_id or display_id,
        "record_id": record_id,
        "source": provider,
        "cnvd_id": display_id,
        "cve_id": cve_ids[0] if cve_ids else None,
        "search_id": (cve_ids[0] if cve_ids else None) or display_id,
        "cve_ids": cve_ids,
        **fields,
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
            log.debug("Skipping news record without provider or record ID: %r", provider)
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


def query_news(providers=None, days=None, record_ids=None):
    if isinstance(providers, str):
        providers = (providers,)
    if providers is not None:
        providers = sorted({str(provider).strip().lower() for provider in providers if str(provider).strip()})
    if providers == [] or (record_ids is not None and not record_ids):
        return []
    cutoff = None
    if days is not None:
        days = int(days)
        if days < 1:
            sys.exit("scrape_days must be >= 1")
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    record_ids = [str(record_id) for record_id in (record_ids or [])]
    log.info(
        "Querying MongoDB (%s.news) providers=%s days=%s ids=%d",
        DB,
        ",".join(provider.upper() for provider in providers) if providers is not None else "all",
        days,
        len(record_ids),
    )
    query = {"source.provider": {"$in": providers} if providers is not None else {"$type": "string", "$nin": [""]}}
    if record_ids:
        query["_id"] = {"$in": record_ids}
    if cutoff:
        query["$or"] = [
            {"observed_at": {"$gte": cutoff}},
            {"scraped_at": {"$gte": cutoff.isoformat()}},
        ]
    return run_mongo(query, sort=[("observed_at", -1), ("scraped_at", -1), ("code", -1)])


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
    if not provider or not identifier:
        return ""
    if identifier.lower().startswith(f"{provider}:"):
        return identifier
    if provider == "cnvd":
        display_id = norm_cnvd(identifier)
        return f"cnvd:{display_id.removeprefix('CNVD-')}"
    if provider == "cnnvd":
        display_id = norm_cnnvd(identifier)
        return f"cnnvd:{display_id.removeprefix('CNNVD-')}"
    return ""  # Other providers require their exact Mongo _id, not a guessed display ID.


def candidates_from_payload(payload):
    matches = payload.get("matches") or []
    if not matches:
        return []
    match_record_ids = [record_id_from_match(match) for match in matches]
    record_ids = list(dict.fromkeys(record_id for record_id in match_record_ids if record_id))
    docs = query_news(record_ids=record_ids)
    candidates = {
        candidate["record_id"]: candidate
        for candidate in docs_to_candidates(docs)
        if candidate.get("record_id")
    }
    ordered = []
    seen = set()
    for match, record_id in zip(matches, match_record_ids):
        candidate = candidates.get(record_id)
        if not candidate or record_id in seen:
            continue
        seen.add(record_id)
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
