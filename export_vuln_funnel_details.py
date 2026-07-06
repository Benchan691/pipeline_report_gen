#!/usr/bin/env python3
"""One-time funnel dump: every vuln in the match window with stage + match details."""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone

from pipeline.config import load_config
from pipeline.vuln_match import (
    cap_per_cluster,
    doc_date,
    docs_for,
    first_match,
    mark_match,
    norm_id,
    norm_severity,
    ranked_matches,
    searchable_text,
    software_terms,
    vuln_type_key,
)


DEFAULT_OUTPUT = "vuln_match_funnel_details.json"


def cve_id(source, doc):
    raw = (doc.get("details") or {}).get(source) or {}
    if source == "cnvd":
        ids = raw.get("cve_ids") or doc.get("cve_codes") or []
        return ids[0] if ids else None
    return raw.get("cveId") or ((doc.get("cve_codes") or [None])[0])


def product_fields(source, doc):
    raw = (doc.get("details") or {}).get(source) or {}
    if source == "cnvd":
        return {
            "title": doc.get("title") or raw.get("title") or "",
            "affected_products": raw.get("affected_products") or [],
        }
    return {
        "title": doc.get("title") or raw.get("vulName") or "",
        "product_name": raw.get("productName") or "",
        "vendor_name": raw.get("vendorName") or "",
    }


def base_record(source, doc):
    severity = norm_severity(doc.get("severity") or doc.get("status"))
    products = product_fields(source, doc)
    return {
        "source": source,
        "id": norm_id(source, doc.get("code")),
        "severity": severity,
        "cve_id": cve_id(source, doc),
        "published": doc_date(doc),
        "title": products.get("title") or doc.get("title") or "",
        "product_fields": products,
        "searchable_text": searchable_text(source, doc),
    }


def match_record(base, match, mark, reasons):
    return {
        **base,
        "mark": mark,
        "mark_reasons": reasons,
        "matched_software": match["term"],
        "match_term_kind": match.get("term_kind"),
        "cluster_id": match["cluster_id"],
        "cluster_label": match["cluster_label"],
        "cluster_size": match["cluster_size"],
        "vuln_type_key": vuln_type_key(base["title"], match.get("cluster_label")),
    }


def build_funnel(cfg):
    terms = software_terms(cfg.get("software_cluster_csv", "cluster/software_cluster_summary_v3.csv"))
    allowed = {norm_severity(s) for s in cfg.get("severity_filter", []) if str(s).strip()}
    days = cfg.get("vuln_match_scrape_days", cfg.get("scrape_days"))
    top_n = int(cfg.get("vuln_match_top_n", 20))
    max_per_cluster = int(cfg.get("vuln_match_max_per_cluster") or 0)

    filtered_severity = []
    filtered_no_match = []
    filtered_duplicate = []
    marked = []
    seen = set()
    total_by_source = Counter()

    for source in ("cnvd", "cnnvd"):
        for doc in docs_for(source, days):
            total_by_source[source] += 1
            base = base_record(source, doc)
            severity = base["severity"]
            if allowed and severity not in allowed:
                filtered_severity.append({**base, "filter_reason": "severity"})
                continue
            match = first_match(terms, base["searchable_text"])
            if not match:
                filtered_no_match.append({**base, "filter_reason": "no_software_match"})
                continue
            if base["id"] in seen:
                filtered_duplicate.append({**base, "filter_reason": "duplicate_id"})
                continue
            seen.add(base["id"])
            mark, reasons = mark_match(severity, match, base["published"])
            marked.append(match_record(base, match, mark, reasons))

    capped = cap_per_cluster(marked, max_per_cluster) if max_per_cluster else list(marked)
    capped_ids = {m["id"] for m in capped}
    cluster_cap_dropped = [m for m in marked if m["id"] not in capped_ids]
    final = ranked_matches(capped, top_n)
    final_ids = {m["id"] for m in final}
    top_n_dropped = [m for m in capped if m["id"] not in final_ids]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "scrape_days": days,
            "severity_filter": sorted(allowed),
            "vuln_match_top_n": top_n,
            "vuln_match_max_per_cluster": max_per_cluster,
            "software_cluster_csv": cfg.get("software_cluster_csv"),
            "match_fields": "title and product fields only (no description)",
            "software_terms_count": len(terms),
        },
        "funnel": {
            "total_in_window": sum(total_by_source.values()),
            "by_source": dict(total_by_source),
            "filtered_severity": len(filtered_severity),
            "filtered_no_software_match": len(filtered_no_match),
            "filtered_duplicate": len(filtered_duplicate),
            "marked": len(marked),
            "after_cluster_cap": len(capped),
            "cluster_cap_dropped": len(cluster_cap_dropped),
            "final_top_n": len(final),
            "top_n_dropped": len(top_n_dropped),
        },
        "filtered_by_severity": filtered_severity,
        "filtered_no_software_match": filtered_no_match,
        "filtered_duplicate": filtered_duplicate,
        "marked": marked,
        "after_cluster_cap": capped,
        "cluster_cap_dropped": cluster_cap_dropped,
        "final_export": final,
        "top_n_dropped": top_n_dropped,
    }


def main():
    parser = argparse.ArgumentParser(description="Dump vuln match funnel details to JSON.")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    payload = build_funnel(load_config(args.config))
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    f = payload["funnel"]
    print("wrote %s" % args.output)
    print(
        "total=%d -> severity=%d, no_match=%d, dup=%d, marked=%d -> "
        "cluster_cap=%d (dropped %d) -> final=%d (dropped %d)"
        % (
            f["total_in_window"],
            f["filtered_severity"],
            f["filtered_no_software_match"],
            f["filtered_duplicate"],
            f["marked"],
            f["after_cluster_cap"],
            f["cluster_cap_dropped"],
            f["final_top_n"],
            f["top_n_dropped"],
        )
    )


if __name__ == "__main__":
    main()
