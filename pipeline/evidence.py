import http.client
import json
import logging
import sys
import urllib.error
import urllib.request

from pipeline.constants import CONFIDENCE, EVIDENCE_KEYS
from pipeline.utils import short_url, unique

log = logging.getLogger(__name__)


def call_ai(base_url, model, system, user, max_tokens=1000):
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        base_url.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as res:
            body = json.loads(res.read().decode("utf-8"))
    except (urllib.error.URLError, http.client.HTTPException) as exc:
        sys.exit(f"AI request failed: {exc}")
    msg = body["choices"][0]["message"]
    return msg.get("content") or msg.get("reasoning_content") or ""


def extract_json(text):
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("AI response did not contain JSON")
    return json.loads(text[start:end + 1])


def normalize_card(raw, result, candidate):
    card = {
        "cnvd_id": candidate["cnvd_id"],
        "cve_id": candidate.get("cve_id"),
        "search_id": candidate["search_id"],
        "title": candidate["title"],
        "what_happened": "",
        "why_matters": "",
        "how_to_respond": "",
        "affected_versions": [],
        "fixed_versions": [],
        "cvss_score": None,
        "cvss_vector": None,
        "references": [],
        "confidence": "low",
        "task_type": result.get("task_type"),
        "source_url": result.get("url") or "",
    }
    if isinstance(raw, dict):
        card.update(raw.get("card") if isinstance(raw.get("card"), dict) else raw)
    for key in ("cnvd_id", "search_id", "title", "what_happened", "why_matters", "how_to_respond", "cvss_vector", "confidence"):
        card[key] = "" if card.get(key) is None else str(card.get(key)).strip()
    card["cnvd_id"] = candidate["cnvd_id"]
    card["cve_id"] = candidate.get("cve_id")
    card["search_id"] = candidate["search_id"]
    card["confidence"] = card["confidence"] if card["confidence"] in CONFIDENCE else "low"
    for key in ("affected_versions", "fixed_versions", "references"):
        value = card.get(key)
        if isinstance(value, str):
            value = [value] if value.strip() else []
        card[key] = [str(v).strip() for v in (value or []) if str(v).strip()]
    if card["source_url"] and card["source_url"] not in card["references"]:
        card["references"].append(card["source_url"])
    return card


def evidence_prompt(result, candidate, lang):
    language = "Simplified Chinese" if lang == "zh" else "English"
    system = (
        f"Extract cybersecurity evidence in {language}. Use only the supplied search result. "
        "Return one strict JSON object only. If a field is unsupported, use empty string, empty array, or null. "
        "confidence must be high, medium, or low."
    )
    user = {
        "required_keys": EVIDENCE_KEYS,
        "task_type": result["task_type"],
        "candidate": {k: candidate.get(k) for k in ("cnvd_id", "cve_id", "search_id", "title", "severity", "summary")},
        "source": {k: result.get(k) for k in ("url", "title", "snippet", "page_content")},
    }
    return system, json.dumps(user, ensure_ascii=False)


def extract_evidence_cards(candidates, results, cfg):
    by_candidate = {c["candidate_id"]: c for c in candidates}
    cards = []
    total = len(results)
    log.info("Extracting evidence with AI (%s, model=%s)", cfg["ai_base_url"], cfg["ai_model"])
    for index, result in enumerate(results, 1):
        candidate = by_candidate[result["candidate_id"]]
        log.info(
            "[%d/%d] %s / %s <- %s",
            index,
            total,
            result["cnvd_id"],
            result["task_type"],
            short_url(result.get("url")),
        )
        system, user = evidence_prompt(result, candidate, cfg["lang"])
        text = call_ai(cfg["ai_base_url"], cfg["ai_model"], system, user)
        try:
            raw = extract_json(text)
        except Exception:
            log.warning("  AI response was not valid JSON for %s / %s", result["cnvd_id"], result["task_type"])
            raw = {}
        card = normalize_card(raw, result, candidate)
        log.info("  confidence=%s", card["confidence"])
        cards.append(card)
    log.info("AI extraction done: %d evidence card(s)", len(cards))
    return cards


def pick(cards, task_type):
    options = [c for c in cards if c.get("task_type") == task_type and c.get(task_type)]
    if not options:
        return ""
    options.sort(key=lambda c: (CONFIDENCE.get(c["confidence"], 0), len(c.get(task_type, ""))), reverse=True)
    return options[0][task_type]


def merge_cards(candidates, evidence_cards):
    by_candidate = {}
    for card in evidence_cards:
        by_candidate.setdefault(card["cnvd_id"], []).append(card)
    merged = []
    log.info("Merging evidence into %d vulnerability card(s)", len(candidates))
    for c in candidates:
        cards = by_candidate.get(c["cnvd_id"], [])
        refs = unique(c.get("references", []) + [r for card in cards for r in card.get("references", [])])
        merged.append({
            "cnvd_id": c["cnvd_id"],
            "source": c.get("source", "cnvd"),
            "cve_id": c.get("cve_id"),
            "search_id": c["search_id"],
            "title": next((card["title"] for card in cards if card.get("title")), c["title"]),
            "severity": c.get("severity"),
            "what_happened": pick(cards, "what_happened") or c.get("summary") or "",
            "why_matters": pick(cards, "why_matters"),
            "how_to_respond": pick(cards, "how_to_respond") or c.get("solution") or "",
            "affected_products": c.get("affected_products") or [],
            "cluster_label": c.get("cluster_label") or "",
            "matched_software": c.get("matched_software") or "",
            "affected_versions": unique([v for card in cards for v in card.get("affected_versions", [])]),
            "fixed_versions": unique([v for card in cards for v in card.get("fixed_versions", [])]),
            "references": refs,
            "mark": c.get("mark"),
            "mark_reasons": c.get("mark_reasons") or [],
            "doc": c["doc"],
        })
        log.info(
            "  %s: what=%d chars, why=%d chars, how=%d chars",
            c["cnvd_id"],
            len(merged[-1]["what_happened"]),
            len(merged[-1]["why_matters"]),
            len(merged[-1]["how_to_respond"]),
        )
    return merged


def write_evidence(path, candidates, search_results, evidence_cards, merged_cards):
    log.info("Writing evidence JSON to %s", path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "candidates": [{k: v for k, v in c.items() if k != "doc"} for c in candidates],
            "search_results": search_results,
            "source_evidence_cards": evidence_cards,
            "vulnerability_cards": [{k: v for k, v in c.items() if k != "doc"} for c in merged_cards],
        }, f, ensure_ascii=False, indent=2)


def clear_evidence(path):
    log.info("Clearing evidence JSON at %s", path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "candidates": [],
            "search_results": [],
            "source_evidence_cards": [],
            "vulnerability_cards": [],
        }, f, ensure_ascii=False, indent=2)


def load_existing_evidence(path, candidates):
    log.info("Loading existing evidence from %s", path)
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    cards = payload.get("vulnerability_cards", payload) if isinstance(payload, dict) else payload
    if not cards:
        log.info("Existing evidence is empty; regenerating evidence")
        return None
    by_id = {c["cnvd_id"]: c for c in cards}
    merged = []
    for candidate in candidates:
        card = dict(by_id.get(candidate["cnvd_id"]) or {})
        card.setdefault("cnvd_id", candidate["cnvd_id"])
        card.setdefault("source", candidate.get("source", "cnvd"))
        card.setdefault("cve_id", candidate.get("cve_id"))
        card.setdefault("search_id", candidate["search_id"])
        card.setdefault("title", candidate["title"])
        card.setdefault("what_happened", candidate.get("summary") or "")
        card.setdefault("why_matters", "")
        card.setdefault("how_to_respond", candidate.get("solution") or "")
        card.setdefault("affected_products", candidate.get("affected_products") or [])
        card.setdefault("cluster_label", candidate.get("cluster_label") or "")
        card.setdefault("matched_software", candidate.get("matched_software") or "")
        card.setdefault("references", candidate.get("references") or [])
        card.setdefault("mark", candidate.get("mark"))
        card.setdefault("mark_reasons", candidate.get("mark_reasons") or [])
        card["doc"] = candidate["doc"]
        merged.append(card)
    log.info("Loaded %d vulnerability card(s) from evidence JSON", len(merged))
    return merged
