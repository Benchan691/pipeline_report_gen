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


def build_filtered_matches(cfg):
    terms = software_terms(cfg.get("software_cluster_csv", "cluster/software_cluster_summary_v3.csv"))
    allowed = {norm_severity(s) for s in cfg.get("severity_filter", []) if str(s).strip()}
    days = cfg.get("vuln_match_scrape_days", cfg.get("scrape_days"))
    top_n = int(cfg.get("vuln_match_top_n", 20))
    max_per_cluster = int(cfg.get("vuln_match_max_per_cluster") or 0)
    matches = []
    seen = set()
    for source in ("cnvd", "cnnvd"):
        for doc in docs_for(source, days):
            severity = norm_severity(doc.get("severity") or doc.get("status"))
            if allowed and severity not in allowed:
                continue
            match = first_match(terms, searchable_text(source, doc))
            if not match:
                continue
            vid = norm_id(source, doc.get("code"))
            if vid in seen:
                continue
            seen.add(vid)
            published = doc_date(doc)
            mark, reasons = mark_match(severity, match, published)
            matches.append({
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
            })
    capped = cap_per_cluster(matches, max_per_cluster) if max_per_cluster else matches
    payload = make_payload(ranked_matches(capped, top_n))
    return payload, {"marked": len(matches), "after_cluster_cap": len(capped)}


def load_filtered_candidates(cfg):
    from pipeline.mongo import candidates_from_payload

    log.info("Matching vulnerabilities against software clusters")
    payload, stats = build_filtered_matches(cfg)
    candidates = candidates_from_payload(payload)
    if not candidates:
        sys.exit("No vulnerabilities matched software clusters in the configured window.")
    return candidates, stats


def self_test():
    assert clean_term("Java 8 Update 202 (64-bit)") == "Java"
    assert clean_term("Microsoft SQL Server 2008 R2 (64-bit)") == "Microsoft SQL Server R2"
    assert norm_severity("高危") == "High"
    assert norm_severity("中\n(AV:L)") == "Medium"
    assert norm_id("cnvd", "2026-24916") == "CNVD-2026-24916"
    assert norm_id("cnnvd", "CNNVD-2026-32651935") == "CNNVD-2026-32651935"
    assert first_match([{"term": "Microsoft Office"}], "microsoft office code execution")

    conductor_doc = {
        "title": "Conductor OSS Conductor 代码注入漏洞",
        "details": {
            "cnnvd": {
                "vulName": "Conductor OSS Conductor 代码注入漏洞",
                "vulDesc": "恶意JavaScript或Python表达式的内联工作流定义",
                "productName": "Conductor",
                "vendorName": "Conductor OSS",
            }
        },
    }
    crawl4ai_doc = {
        "title": "UncleCode Crawl4AI 代码注入漏洞",
        "details": {
            "cnnvd": {
                "vulName": "UncleCode Crawl4AI 代码注入漏洞",
                "vulDesc": "执行攻击者提供的任意JavaScript",
                "productName": "Crawl4AI",
                "vendorName": "UncleCode",
            }
        },
    }
    chrome_doc = {
        "title": "Google Chrome 资源管理错误漏洞",
        "details": {
            "cnnvd": {
                "vulName": "Google Chrome 资源管理错误漏洞",
                "vulDesc": "Blink组件内存错误",
                "productName": "Google Chrome",
                "vendorName": "Google",
            }
        },
    }
    terms = [{"term": "Python"}, {"term": "Java"}, {"term": "Google Chrome"}]
    assert first_match(terms, searchable_text("cnnvd", conductor_doc)) is None
    assert first_match(terms, searchable_text("cnnvd", crawl4ai_doc)) is None
    assert first_match(terms, searchable_text("cnnvd", chrome_doc))["term"] == "Google Chrome"
    high = {"term": "A", "term_kind": "sample", "cluster_size": 1}
    low = {"term": "B", "term_kind": "label", "cluster_size": 99}
    assert mark_match("High", high, "")[0] > mark_match("Medium", low, "")[0]
    ranked = ranked_matches([
        {"source": "cnvd", "id": "CNVD-1", "severity": "High", "mark": 1},
        {"source": "cnvd", "id": "CNVD-2", "severity": "Critical", "mark": 2},
    ], 1)
    assert [m["id"] for m in ranked] == ["CNVD-2"]
    payload = make_payload([{"source": "cnvd", "id": "CNVD-1"}, {"source": "cnnvd", "id": "CNNVD-1"}])
    assert payload["cnvd_ids"] == ["CNVD-1"] and payload["cnnvd_ids"] == ["CNNVD-1"]

    assert vuln_type_key("Google Chrome Blink内存错误引用漏洞", "Google Chrome") == "blink内存错误引用"
    assert vuln_type_key("Google Chrome V8类型混淆漏洞", "Google Chrome") == "v8类型混淆"

    chrome_items = [
        {"id": "C1", "severity": "Critical", "mark": 452, "published": "2026-06-28", "title": "Google Chrome Blink内存错误引用漏洞", "cluster_label": "Google Chrome", "cluster_id": "C0115"},
        {"id": "C2", "severity": "Critical", "mark": 452, "published": "2026-06-29", "title": "Google Chrome V8类型混淆漏洞", "cluster_label": "Google Chrome", "cluster_id": "C0115"},
        {"id": "C3", "severity": "Critical", "mark": 452, "published": "2026-06-30", "title": "Google Chrome WebRTC堆缓冲区溢出漏洞", "cluster_label": "Google Chrome", "cluster_id": "C0115"},
    ]
    diverse = diversity_pick(chrome_items, 3)
    assert len(diverse) == 3
    assert len({vuln_type_key(m["title"], m["cluster_label"]) for m in diverse}) == 3

    many_chrome = [
        {"id": f"C{i}", "severity": "Critical", "mark": 452, "published": "2026-06-30", "title": f"Google Chrome Type{i}漏洞", "cluster_label": "Google Chrome", "cluster_id": "C0115"}
        for i in range(10)
    ]
    java_items = [
        {"id": "J1", "severity": "Critical", "mark": 469, "published": "2026-06-30", "title": "Java RCE漏洞", "cluster_label": "Java", "cluster_id": "C0003"},
        {"id": "J2", "severity": "High", "mark": 366, "published": "2026-06-30", "title": "Java反序列化漏洞", "cluster_label": "Java", "cluster_id": "C0003"},
    ]
    capped = cap_per_cluster(many_chrome + java_items, 5)
    assert len(capped) == 7
    assert len([m for m in capped if m["cluster_id"] == "C0115"]) == 5

    integration = ranked_matches(cap_per_cluster(chrome_items, 5), 3)
    assert len(integration) == 3
