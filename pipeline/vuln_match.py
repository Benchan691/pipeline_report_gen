import csv
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

from pipeline.constants import DB
from pipeline.mongo import candidates_from_payload, run_mongo
from pipeline.utils import norm_cnvd, norm_cnnvd

log = logging.getLogger(__name__)

COMMON_WORDS = {
    "update", "setup", "installer", "install", "uninstall", "driver", "package",
    "x64", "x86", "bit", "edition", "version", "release", "runtime", "client",
}
SEVERITY = {
    "critical": "Critical", "超危": "Critical", "严重": "Critical",
    "high": "High", "高": "High", "高危": "High", "high-risk": "High",
    "medium": "Medium", "中": "Medium", "中危": "Medium", "medium-risk": "Medium",
    "low": "Low", "低": "Low", "低危": "Low", "low-risk": "Low",
}
SEVERITY_MARK = {"Critical": 400, "High": 300, "Medium": 200, "Low": 100}


def norm_severity(value):
    text = str(value or "").strip()
    first = re.split(r"[\s(（]", text, maxsplit=1)[0]
    return SEVERITY.get(first.lower(), SEVERITY.get(first, text))


def norm_id(source, code):
    if source == "cnvd":
        return norm_cnvd(code)
    return norm_cnnvd(code)


def clean_term(value):
    text = re.sub(r"\([^)]*\)", " ", str(value or ""))
    text = re.sub(r"\b(?:v(?:ersion)?\s*)?\d+(?:\.\d+){0,4}\b", " ", text, flags=re.I)
    text = re.sub(r"\b(?:19|20)\d\d[-/.]\d{1,2}[-/.]\d{1,2}\b", " ", text)
    text = re.sub(r"\b(?:32|64)[-\s]?bit\b", " ", text, flags=re.I)
    text = re.sub(r"[_/\\,;:]+", " ", text)
    words = [w for w in re.split(r"\s+", text.strip()) if w and w.lower() not in COMMON_WORDS]
    return " ".join(words)


def software_terms(path):
    by_term = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            values = [("label", row.get("cluster_label_v3", ""))]
            values.extend(("sample", v) for v in row.get("sample_software", "").split("|"))
            for kind, value in values:
                term = clean_term(value)
                if len(term) < 3 or term.lower() in COMMON_WORDS:
                    continue
                if len(term.split()) == 1 and len(term) < 4:
                    continue
                by_term.setdefault(term.lower(), {
                    "term": term,
                    "term_kind": kind,
                    "cluster_id": row.get("cluster_id_v3", ""),
                    "cluster_label": row.get("cluster_label_v3", ""),
                    "cluster_size": int(row.get("cluster_size_v3") or 0),
                })
    return sorted(by_term.values(), key=lambda x: len(x["term"]), reverse=True)


def docs_for(source, days):
    cutoff = ""
    if days is not None:
        cutoff = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - int(days) * 86400, timezone.utc).isoformat()
    script = """
const q = __CUTOFF__ ? {scraped_at: {$gte: __CUTOFF__}} : {};
const docs = db.getSiblingDB("__DB__").getCollection("__COLL__").find(q, {
  code: 1, title: 1, severity: 1, status: 1, cve_codes: 1, details: 1,
  disclosure_date: 1, published_time: 1, scraped_at: 1
}).toArray();
print(JSON.stringify(docs));
""".replace("__DB__", DB).replace("__COLL__", source).replace("__CUTOFF__", json.dumps(cutoff))
    return run_mongo(script)


def searchable_text(source, doc):
    raw = (doc.get("details") or {}).get(source) or {}
    if source == "cnvd":
        parts = [
            doc.get("title"),
            raw.get("title"),
            " ".join(raw.get("affected_products") or []),
        ]
    else:
        parts = [
            doc.get("title"),
            raw.get("vulName"),
            raw.get("productName"),
            raw.get("vendorName"),
        ]
    return "\n".join(str(p) for p in parts if p).lower()


def first_match(terms, text):
    for item in terms:
        term = item["term"].lower()
        if term in text:
            return item
    return None


def doc_fields(source, doc):
    raw = (doc.get("details") or {}).get(source) or {}
    if source == "cnvd":
        return {
            "title": raw.get("title") or doc.get("title") or "",
            "product": " ".join(raw.get("affected_products") or []),
            "vendor": "",
            "summary": str(raw.get("description") or "")[:500],
        }
    return {
        "title": raw.get("vulName") or doc.get("title") or "",
        "product": raw.get("productName") or "",
        "vendor": raw.get("vendorName") or "",
        "summary": str(raw.get("vulDesc") or raw.get("vulDetail") or "")[:500],
    }


def match_confirmation_prompt(doc, source, match):
    fields = doc_fields(source, doc)
    system = (
        "You are a conservative vulnerability-to-installed-software matcher. "
        "The keyword match is an untrusted candidate-generation hint, not evidence of a relationship. "
        "Minimize false positives: when evidence is missing, ambiguous, indirect, or conflicting, return related=false.\n\n"
        "Return exactly one JSON object with exactly these keys: related, confidence, reason. "
        "related must be a JSON boolean. confidence must be \"high\", \"medium\", or \"low\". "
        "reason must briefly name the affected product and explain the product relationship.\n\n"
        "Return related=true only when ALL of these conditions are satisfied:\n"
        "1. The vulnerability record explicitly identifies the affected product in the title or product field, "
        "or the summary explicitly states that the product is vulnerable. A mere mention is insufficient.\n"
        "2. That affected product is exactly the matched cluster software, or an unambiguous edition/component "
        "that belongs to and is shipped as part of that same product.\n"
        "3. The flaw is in that product itself, not in separate software that integrates with, embeds, bundles, "
        "depends on, manages, scans, connects to, or merely supports it.\n"
        "4. The relationship can be established without relying only on a shared vendor, substring, acronym, "
        "generic word, or product-family resemblance.\n"
        "5. Confidence is high. A medium- or low-confidence relationship must be related=false.\n\n"
        "Always return related=false for:\n"
        "- partial-name and lexical collisions (for example Java vs JavaScript)\n"
        "- a language, runtime, SDK, API, protocol, file format, feature, or expression mentioned inside another product\n"
        "- plugins, connectors, integrations, extensions, management tools, or third-party modules whose own code is vulnerable\n"
        "- bundled or transitive dependencies unless the vulnerability record identifies the installed cluster software itself as affected\n"
        "- different products from the same vendor, or products that merely share a suite/ecosystem/brand name\n"
        "- cases supported only by the summary while the title/product field identifies a different affected product\n"
        "- any case requiring outside assumptions about packaging, deployment, aliases, or product lineage\n\n"
        "Positive example: cluster Google Chrome; affected product Google Chrome -> related=true.\n"
        "Negative example: cluster Python; affected product Snowflake Snowpark Python SDK -> related=false.\n"
        "Negative example: cluster OpenSSL; affected product is another application that merely bundles OpenSSL -> related=false."
    )
    user = {
        "matched_term": match.get("term") or "",
        "cluster_label": match.get("cluster_label") or "",
        "vuln_id": norm_id(source, doc.get("code")),
        "title": fields["title"],
        "product": fields["product"],
        "vendor": fields["vendor"],
        "summary": fields["summary"],
    }
    return system, json.dumps(user, ensure_ascii=False)


def match_detail(source, doc, match):
    fields = doc_fields(source, doc)
    return {
        "id": norm_id(source, doc.get("code")),
        "title": fields["title"] or doc.get("title") or "",
        "product": fields["product"],
        "vendor": fields["vendor"],
        "severity": norm_severity(doc.get("severity") or doc.get("status")),
        "term": match.get("term") or "",
        "cluster_id": match.get("cluster_id") or "",
        "cluster_label": match.get("cluster_label") or "",
        "term_kind": match.get("term_kind") or "",
        "cluster_size": match.get("cluster_size") or 0,
    }


def confirm_software_match(doc, source, match, cfg):
    from pipeline.evidence import call_ai, extract_json

    system, user = match_confirmation_prompt(doc, source, match)
    thinking_budget = cfg.get("vuln_match_thinking_budget_tokens")
    try:
        text = call_ai(
            cfg["ai_base_url"],
            cfg["ai_model"],
            system,
            user,
            max_tokens=int(cfg.get("vuln_match_ai_max_tokens", 4096)),
            enable_thinking=True,
            thinking_budget_tokens=thinking_budget,
        )
    except (Exception, SystemExit):
        log.warning(
            "LLM match confirmation unavailable for %s / %s",
            norm_id(source, doc.get("code")),
            match.get("term"),
        )
        return {"related": False, "confidence": "low", "reason": "llm_unavailable"}
    try:
        raw = extract_json(text)
    except Exception:
        log.warning(
            "LLM match confirmation returned invalid JSON for %s / %s",
            norm_id(source, doc.get("code")),
            match.get("term"),
        )
        return {"related": False, "confidence": "low", "reason": "invalid_llm_response"}
    related = raw.get("related") is True
    confidence = str(raw.get("confidence") or "low").strip().lower()
    if confidence not in ("high", "medium", "low"):
        confidence = "low"
    reason = str(raw.get("reason") or "").strip() or "no_reason"
    return {"related": related, "confidence": confidence, "reason": reason}


def doc_date(doc):
    raw = (doc.get("details") or {}).get("cnvd") or (doc.get("details") or {}).get("cnnvd") or {}
    return (
        raw.get("published_date") or raw.get("publishDate") or
        doc.get("disclosure_date") or doc.get("published_time") or doc.get("scraped_at") or ""
    )


def freshness_points(value):
    text = str(value or "")[:10]
    try:
        age = (datetime.now(timezone.utc).date() - datetime.fromisoformat(text).date()).days
    except ValueError:
        return 0
    if age <= 7:
        return 9
    if age <= 30:
        return 6
    if age <= 90:
        return 3
    return 0


def mark_match(severity, match, published):
    reasons = []
    score = SEVERITY_MARK.get(severity, 0)
    reasons.append(f"severity:{severity}+{score}")
    match_points = 40 if match.get("term_kind") == "label" else 20
    score += match_points
    reasons.append(f"{match.get('term_kind', 'match')}:{match['term']}+{match_points}")
    cluster_points = min(int(match.get("cluster_size") or 0), 20)
    score += cluster_points
    reasons.append(f"cluster_size_cap+{cluster_points}")
    fresh = freshness_points(published)
    score += fresh
    if fresh:
        reasons.append(f"freshness+{fresh}")
    return score, reasons


def make_payload(matches):
    return {
        "cnvd_ids": [m["id"] for m in matches if m["source"] == "cnvd"],
        "cnnvd_ids": [m["id"] for m in matches if m["source"] == "cnnvd"],
        "matches": matches,
    }


def vuln_type_key(title, cluster_label=""):
    t = str(title or "")
    if cluster_label:
        t = re.sub(re.escape(cluster_label), "", t, flags=re.I)
    t = re.sub(r"\s*漏洞.*$", "", t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    return t or str(title or "").lower()


def _published_sort_key(value):
    try:
        return datetime.fromisoformat(str(value or "")[:10])
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def cluster_sort_key(match):
    return (
        -SEVERITY_MARK.get(match["severity"], 0),
        -match["mark"],
        -_published_sort_key(match.get("published")).timestamp(),
        match["id"],
    )


def diversity_pick(items, k):
    if k <= 0 or not items:
        return []
    ranked = sorted(items, key=cluster_sort_key)
    picked = []
    seen_types = set()
    for item in ranked:
        if len(picked) >= k:
            break
        type_key = vuln_type_key(item.get("title"), item.get("cluster_label"))
        if type_key not in seen_types:
            picked.append(item)
            seen_types.add(type_key)
    if len(picked) < k:
        picked_ids = {item["id"] for item in picked}
        for item in ranked:
            if len(picked) >= k:
                break
            if item["id"] not in picked_ids:
                picked.append(item)
                picked_ids.add(item["id"])
    return picked


def cap_per_cluster(matches, max_per_cluster):
    groups = defaultdict(list)
    for match in matches:
        groups[match["cluster_id"]].append(match)
    selected = []
    for cluster_id in sorted(groups):
        selected.extend(diversity_pick(groups[cluster_id], max_per_cluster))
    return selected


def ranked_matches(matches, top_n):
    return sorted(matches, key=lambda m: (-m["mark"], -SEVERITY_MARK.get(m["severity"], 0), m.get("published") or "", m["id"]))[:top_n]


def select_confirmed_matches(pending, cfg, top_n, max_per_cluster):
    selected = []
    llm_rejected = 0
    cluster_cap_skipped = 0
    cluster_counts = defaultdict(int)
    for candidate in sorted(
        pending,
        key=lambda candidate: (
            -candidate["item"]["mark"],
            -SEVERITY_MARK.get(candidate["item"]["severity"], 0),
            candidate["item"].get("published") or "",
            candidate["item"]["id"],
        ),
    ):
        if len(selected) >= top_n:
            break
        item = candidate["item"]
        cluster_id = item["cluster_id"]
        if max_per_cluster and cluster_counts[cluster_id] >= max_per_cluster:
            cluster_cap_skipped += 1
            log.info(
                "  Cluster cap skipped %s [%s] cluster=%s mark=%d title=%s",
                item["id"], item["severity"], item["cluster_label"], item["mark"], item["title"],
            )
            continue
        confirmation = confirm_software_match(candidate["doc"], item["source"], candidate["match"], cfg)
        if not confirmation["related"]:
            llm_rejected += 1
            log.info(
                "  LLM rejected %s term=%r confidence=%s reason=%s",
                item["id"], item["matched_software"], confirmation["confidence"], confirmation["reason"],
            )
            continue
        item["mark_reasons"].extend((
            f"llm_related:{confirmation['confidence']}",
            f"llm_reason:{confirmation['reason']}",
        ))
        cluster_counts[cluster_id] += 1
        selected.append(item)
        log.info(
            "  LLM accepted %s term=%r cluster=%s mark=%d confidence=%s reason=%s",
            item["id"], item["matched_software"], item["cluster_label"], item["mark"],
            confirmation["confidence"], confirmation["reason"],
        )
    if len(selected) < top_n:
        log.warning("  Shortlist shortfall: requested=%d accepted=%d", top_n, len(selected))
    return selected, llm_rejected, cluster_cap_skipped


def build_filtered_matches(cfg):
    terms = software_terms(cfg.get("software_cluster_csv", "cluster/software_cluster_summary_v3.csv"))
    allowed = {norm_severity(s) for s in cfg.get("severity_filter", []) if str(s).strip()}
    days = cfg.get("vuln_match_scrape_days", cfg.get("scrape_days"))
    top_n = int(cfg.get("vuln_match_top_n", 20))
    max_per_cluster = int(cfg.get("vuln_match_max_per_cluster") or 0)
    severity_text = ", ".join(sorted(allowed)) if allowed else "all"
    log.info(
        "Cluster matching: %d term(s), severities=%s, scrape_days=%s, top_n=%d, max_per_cluster=%d",
        len(terms),
        severity_text,
        days,
        top_n,
        max_per_cluster,
    )
    pending = []
    seen = set()
    keyword_hits = 0
    for source in ("cnvd", "cnnvd"):
        docs = docs_for(source, days)
        log.info("  Scanning %d %s document(s)", len(docs), source.upper())
        for doc in docs:
            severity = norm_severity(doc.get("severity") or doc.get("status"))
            if allowed and severity not in allowed:
                continue
            match = first_match(terms, searchable_text(source, doc))
            if not match:
                continue
            vid = norm_id(source, doc.get("code"))
            if vid in seen:
                log.info("  Duplicate keyword hit skipped: %s (term=%r)", vid, match["term"])
                continue
            detail = match_detail(source, doc, match)
            seen.add(vid)
            keyword_hits += 1
            log.info(
                "  Keyword hit %s [%s] term=%r (%s) cluster=%s (%s, size=%s) product=%r vendor=%r title=%s",
                detail["id"],
                detail["severity"],
                detail["term"],
                detail["term_kind"],
                detail["cluster_id"],
                detail["cluster_label"],
                detail["cluster_size"],
                detail["product"],
                detail["vendor"],
                detail["title"],
            )
            published = doc_date(doc)
            mark, reasons = mark_match(severity, match, published)
            log.info(
                "  Marked %s term=%r cluster=%s mark=%d",
                detail["id"],
                detail["term"],
                detail["cluster_label"],
                mark,
            )
            pending.append({
                "doc": doc,
                "match": match,
                "item": {
                    "source": source,
                    "id": vid,
                    "severity": severity,
                    "mark": mark,
                    "mark_reasons": reasons,
                    "matched_software": match["term"],
                    "cluster_id": match["cluster_id"],
                    "cluster_label": match["cluster_label"],
                    "cluster_size": match["cluster_size"],
                    "published": published,
                    "title": doc.get("title") or "",
                },
            })
    ranked, llm_rejected, cluster_cap_skipped = select_confirmed_matches(
        pending, cfg, top_n, max_per_cluster,
    )
    for index, item in enumerate(ranked, 1):
        log.info(
            "  Shortlist #%d %s [%s] mark=%d term=%r cluster=%s title=%s",
            index,
            item["id"],
            item["severity"],
            item["mark"],
            item["matched_software"],
            item["cluster_label"],
            item["title"],
        )
    payload = make_payload(ranked)
    log.info(
        "Cluster match filter: keyword_hits=%d marked=%d llm_accepted=%d llm_rejected=%d cluster_cap_skipped=%d shortlisted=%d",
        keyword_hits,
        len(pending),
        len(ranked),
        llm_rejected,
        cluster_cap_skipped,
        len(ranked),
    )
    return payload, {
        "marked": len(pending),
        "after_cluster_cap": len(ranked),
        "keyword_hits": keyword_hits,
        "llm_rejected": llm_rejected,
        "cluster_cap_skipped": cluster_cap_skipped,
        "shortfall": max(0, top_n - len(ranked)),
    }


def load_filtered_candidates(cfg):
    log.info("Matching vulnerabilities against software clusters")
    payload, stats = build_filtered_matches(cfg)
    candidates = candidates_from_payload(payload)
    if not candidates:
        sys.exit("No vulnerabilities matched software clusters in the configured window.")
    return candidates, stats
