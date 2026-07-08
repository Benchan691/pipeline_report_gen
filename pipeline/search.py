import http.client
import json
import logging
import sys
import urllib.error
import urllib.parse
import urllib.request

from pipeline.utils import content_hash

log = logging.getLogger(__name__)


def queries_for_candidate(candidate):
    sid = candidate["search_id"]
    title = candidate["title"]
    if candidate.get("cve_id"):
        return {
            "what_happened": [f"{sid} {title} vulnerability advisory", f"{sid} NVD description"],
            "why_matters": [f"{sid} CVSS score exploit impact", f"{sid} CISA KEV exploited in the wild"],
            "how_to_respond": [f"{sid} patch fixed version", f"{sid} vendor security update"],
        }
    return {
        "what_happened": [f"{sid} {title}", f"{sid} 漏洞"],
        "why_matters": [f"{sid} 危害 影响", f"{sid} CVSS"],
        "how_to_respond": [f"{sid} 修复", f"{sid} 补丁"],
    }


def searxng_search(base_url, query, max_results, timeout=30):
    if not base_url:
        sys.exit("Missing config key: searxng_base_url")
    url = base_url.rstrip("/") + "/search?" + urllib.parse.urlencode({"q": query, "format": "json"})
    try:
        with urllib.request.urlopen(url, timeout=timeout) as res:
            body = json.loads(res.read().decode("utf-8"))
    except (urllib.error.URLError, http.client.HTTPException) as exc:
        sys.exit(f"SearXNG request failed for {query!r}: {exc}")
    raw_items = (body.get("results") or [])[: int(max_results)]
    results = []
    for item in raw_items:
        link = (item.get("url") or "").strip()
        snippet = (item.get("content") or item.get("snippet") or item.get("title") or "").strip()
        if not link or not snippet:
            continue
        results.append({
            "url": link,
            "title": item.get("title") or "",
            "snippet": snippet,
            "page_content": snippet,
            "score": item.get("score") or 0,
            "source_api": "searxng",
            "content_hash": content_hash(link, item.get("title"), snippet),
        })
    if not results and (body.get("unresponsive_engines") or body.get("errors")):
        log.warning(
            "SearXNG returned 0 usable hits for %r; engine issues: %s",
            query,
            body.get("unresponsive_engines") or body.get("errors"),
        )
    return results


def parse_firecrawl_results(body):
    data = body.get("data") or {}
    raw_items = data.get("web") if isinstance(data, dict) else data
    rows = []
    for item in raw_items or []:
        link = (item.get("url") or "").strip()
        snippet = (item.get("description") or item.get("snippet") or item.get("markdown") or item.get("title") or "").strip()
        if not link or not snippet:
            continue
        rows.append({
            "url": link,
            "title": item.get("title") or "",
            "snippet": snippet,
            "page_content": item.get("markdown") or snippet,
            "score": item.get("score") or item.get("position") or 0,
            "source_api": "firecrawl",
            "content_hash": content_hash(link, item.get("title"), snippet),
        })
    return rows


def firecrawl_search(cfg, query, timeout=30):
    api_key = str(cfg.get("firecrawl_api_key") or "").strip()
    if not api_key:
        sys.exit("Missing FIRECRAWL_API_KEY in .env")
    req = urllib.request.Request(
        cfg["firecrawl_base_url"].rstrip("/") + "/v2/search",
        data=json.dumps({"query": query, "limit": int(cfg["firecrawl_max_results"]), "sources": ["web"]}).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = json.loads(res.read().decode("utf-8"))
    except (urllib.error.URLError, http.client.HTTPException) as exc:
        sys.exit(f"Firecrawl request failed for {query!r}: {exc}")
    if not body.get("success", True):
        sys.exit(f"Firecrawl request failed for {query!r}: {body.get('error') or body}")
    return parse_firecrawl_results(body)


def web_search(cfg, query):
    if cfg["search_provider"] == "firecrawl":
        return firecrawl_search(cfg, query)
    hits = searxng_search(cfg["searxng_base_url"], query, cfg["searxng_max_results"])
    if hits or not cfg.get("search_fallback_firecrawl", True) or not cfg.get("firecrawl_api_key"):
        return hits
    log.info("  SearXNG empty for %r; falling back to Firecrawl", query)
    return firecrawl_search(cfg, query)


def rank_score(result, candidate):
    host = urllib.parse.urlparse(result.get("url") or "").hostname or ""
    text = " ".join([host, result.get("title", ""), result.get("snippet", "")]).lower()
    score = 10
    if "nvd.nist.gov" in host or "mitre.org" in host:
        score += 80
    if "cisa.gov" in host:
        score += 70
    if any(word in text for word in ("vendor", "security update", "advisory", "patch", "补丁", "修复")):
        score += 30
    if candidate["search_id"].lower() in text:
        score += 25
    try:
        score += min(float(result.get("score") or 0) * 5, 5)
    except (TypeError, ValueError):
        pass
    return score


def filter_results(results, top_n):
    grouped = {}
    seen = set()
    for result in results:
        key = (result["candidate_id"], result["task_type"], result["url"].rstrip("/").lower())
        if key in seen:
            continue
        seen.add(key)
        grouped.setdefault((result["candidate_id"], result["task_type"]), []).append(result)
    filtered = []
    for group in grouped.values():
        filtered.extend(sorted(group, key=lambda r: r["rank_score"], reverse=True)[:top_n])
    return filtered


def search_candidates(candidates, cfg):
    rows = []
    total = len(candidates)
    log.info("Searching with %s", cfg["search_provider"])
    for index, candidate in enumerate(candidates, 1):
        before = len(rows)
        log.info("[%d/%d] %s (%s): running searches", index, total, candidate["cnvd_id"], candidate["search_id"])
        for task_type, queries in queries_for_candidate(candidate).items():
            for query in queries:
                hits = web_search(cfg, query)
                matched = 0
                for result in hits:
                    text = " ".join([result["url"], result["title"], result["snippet"]]).lower()
                    sid = candidate["search_id"].lower()
                    if sid.lower() not in text and candidate["title"].lower()[:12] not in text:
                        continue
                    matched += 1
                    result.update({
                        "candidate_id": candidate["candidate_id"],
                        "cnvd_id": candidate["cnvd_id"],
                        "cve_id": candidate.get("cve_id"),
                        "search_id": candidate["search_id"],
                        "task_type": task_type,
                        "query": query,
                        "rank_score": rank_score(result, candidate),
                    })
                    rows.append(result)
                log.info("  [%s] %r -> %d/%d hit(s)", task_type, query, matched, len(hits))
        log.info("  %s: %d relevant result(s) so far", candidate["cnvd_id"], len(rows) - before)
    filtered = filter_results(rows, int(cfg["results_per_task"]))
    log.info("Search done: %d raw hit(s), %d kept after ranking", len(rows), len(filtered))
    return filtered
