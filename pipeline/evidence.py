import http.client
import json
import logging
import sys
import urllib.error
import urllib.request

from pipeline.constants import CONFIDENCE, EVIDENCE_KEYS, DEFAULT_REPORT_LANG, REPORT_LANGS
from pipeline.utils import short_url, unique

log = logging.getLogger(__name__)

THINK_CLOSE_TAGS = ("</think>", "</redacted_thinking>")


def strip_thinking(text):
    if not text:
        return ""
    text = str(text)
    for close_tag in THINK_CLOSE_TAGS:
        if close_tag in text:
            return text.split(close_tag, 1)[-1].strip()
    return text.strip()


def build_ai_payload(model, system, user, max_tokens, enable_thinking=False, thinking_budget_tokens=None):
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": max_tokens,
        "chat_template_kwargs": {"enable_thinking": bool(enable_thinking)},
    }
    if enable_thinking and thinking_budget_tokens is not None:
        payload["thinking_budget_tokens"] = int(thinking_budget_tokens)
    return payload


def call_ai(base_url, model, system, user, max_tokens=1000, enable_thinking=False, thinking_budget_tokens=None):
    payload = build_ai_payload(model, system, user, max_tokens, enable_thinking, thinking_budget_tokens)
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
    choice = body["choices"][0]
    msg = choice["message"]
    content = msg.get("content") or ""
    if enable_thinking:
        content = strip_thinking(content)
        if not content and choice.get("finish_reason") == "length":
            return ""
    return content


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


def evidence_prompt(result, candidate):
    system = (
        "You are a cautious cybersecurity analyst. Extract only facts explicitly supported by the supplied source; "
        "do not infer affected versions, exploitability, patches, or impact. Write concise Simplified Chinese. "
        "Prioritize the field named by task_type, but fill any other field only when the source supports it. "
        "Return one JSON object only—no Markdown, explanation, or card wrapper—with exactly these keys: "
        "cnvd_id, cve_id, search_id, title, what_happened, why_matters, how_to_respond, affected_versions, "
        "fixed_versions, cvss_score, cvss_vector, references, confidence. "
        "Use empty strings, empty arrays, or null for unsupported values. Keep versions, CVE/CNVD IDs, CVSS vectors, "
        "and URLs exact. references may contain only the supplied source URL. "
        "Set confidence to high for direct, explicit evidence; medium for relevant but incomplete evidence; otherwise low."
    )
    user = {
        "required_keys": EVIDENCE_KEYS,
        "task_type": result["task_type"],
        "candidate": {k: candidate.get(k) for k in ("cnvd_id", "cve_id", "search_id", "title", "severity", "summary")},
        "source": {k: result.get(k) for k in ("url", "title", "snippet", "page_content")},
    }
    return system, json.dumps(user, ensure_ascii=False)


def translation_prompt(card):
    system = (
        "Translate the supplied cybersecurity report fields from Simplified Chinese to clear, concise English. "
        "Preserve meaning and certainty; do not add remediation, impact, or context. Do not translate CVE/CNVD IDs, "
        "CVSS vectors, version strings, URLs, product names, vendor names, code, or commands. "
        "Return one JSON object only—no Markdown or explanation—with exactly these string keys: title, what_happened, "
        "why_matters, how_to_respond. Preserve empty fields as empty strings."
    )
    user = {
        "title": card.get("title") or "",
        "what_happened": card.get("what_happened") or "",
        "why_matters": card.get("why_matters") or "",
        "how_to_respond": card.get("how_to_respond") or "",
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
        system, user = evidence_prompt(result, candidate)
        text = call_ai(cfg["ai_base_url"], cfg["ai_model"], system, user, enable_thinking=False)
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


def pick_for_lang(cards, task_type, lang=None):
    options = [c for c in cards if c.get("task_type") == task_type and c.get(task_type)]
    if not options:
        return ""
    options.sort(key=lambda c: (CONFIDENCE.get(c["confidence"], 0), len(c.get(task_type, ""))), reverse=True)
    return options[0][task_type]


def localized_field(value, lang, fallback=""):
    if isinstance(value, dict):
        return value.get(lang) or fallback
    if lang == DEFAULT_REPORT_LANG:
        return value or fallback
    return fallback


def normalize_localized_fields(card, warned=None):
    warned = warned if warned is not None else {"missing_en": False}
    for field in ("title", "what_happened", "why_matters", "how_to_respond"):
        value = card.get(field)
        if isinstance(value, dict):
            continue
        text = "" if value is None else str(value)
        card[field] = {DEFAULT_REPORT_LANG: text, "en": ""}
        if text and not warned["missing_en"]:
            warned["missing_en"] = True
    if warned["missing_en"]:
        log.warning("Evidence JSON uses legacy single-language text fields; regenerate evidence for English DOCX content")
    return card


def translate_card_fields(card, cfg):
    system, user = translation_prompt(card)
    text = call_ai(cfg["ai_base_url"], cfg["ai_model"], system, user, enable_thinking=False)
    try:
        raw = extract_json(text)
    except Exception:
        log.warning("  AI translation response was not valid JSON for %s", card["cnvd_id"])
        raw = {}
    translated = {}
    for field in ("title", "what_happened", "why_matters", "how_to_respond"):
        value = raw.get(field)
        translated[field] = "" if value is None else str(value).strip()
    return translated


def add_english_translations(cards, cfg):
    for card in cards:
        zh_card = {field: localized_field(card.get(field), DEFAULT_REPORT_LANG) for field in ("title", "what_happened", "why_matters", "how_to_respond")}
        translated = translate_card_fields(zh_card, cfg)
        for field in ("title", "what_happened", "why_matters", "how_to_respond"):
            value = card.get(field)
            if not isinstance(value, dict):
                value = {DEFAULT_REPORT_LANG: localized_field(value, DEFAULT_REPORT_LANG), "en": ""}
            value["en"] = translated[field]
            card[field] = value
    return cards


def card_missing_english(card):
    for field in ("title", "what_happened", "why_matters", "how_to_respond"):
        value = card.get(field)
        if not isinstance(value, dict):
            return True
        zh_text = str(value.get(DEFAULT_REPORT_LANG) or "").strip()
        en_text = str(value.get("en") or "").strip()
        if zh_text and not en_text:
            return True
    return False


def cards_missing_english(cards):
    return any(card_missing_english(card) for card in cards)


def merge_cards(candidates, evidence_cards):
    by_candidate = {}
    for card in evidence_cards:
        by_candidate.setdefault(card["cnvd_id"], []).append(card)
    merged = []
    log.info("Merging evidence into %d vulnerability card(s)", len(candidates))
    for c in candidates:
        cards = by_candidate.get(c["cnvd_id"], [])
        refs = unique(c.get("references", []) + [r for card in cards for r in card.get("references", [])])
        localized = {}
        localized["title"] = {DEFAULT_REPORT_LANG: next((card["title"] for card in cards if card.get("title")), c["title"]), "en": ""}
        localized["what_happened"] = {DEFAULT_REPORT_LANG: pick_for_lang(cards, "what_happened") or c.get("summary") or "", "en": ""}
        localized["why_matters"] = {DEFAULT_REPORT_LANG: pick_for_lang(cards, "why_matters"), "en": ""}
        localized["how_to_respond"] = {DEFAULT_REPORT_LANG: pick_for_lang(cards, "how_to_respond") or c.get("solution") or "", "en": ""}
        merged.append({
            "cnvd_id": c["cnvd_id"],
            "source": c.get("source", "cnvd"),
            "cve_id": c.get("cve_id"),
            "search_id": c["search_id"],
            "title": localized["title"],
            "severity": c.get("severity"),
            "what_happened": localized["what_happened"],
            "why_matters": localized["why_matters"],
            "how_to_respond": localized["how_to_respond"],
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
            len(localized_field(merged[-1]["what_happened"], DEFAULT_REPORT_LANG)),
            len(localized_field(merged[-1]["why_matters"], DEFAULT_REPORT_LANG)),
            len(localized_field(merged[-1]["how_to_respond"], DEFAULT_REPORT_LANG)),
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


def _empty_evidence_payload():
    return {
        "candidates": [],
        "search_results": [],
        "source_evidence_cards": [],
        "vulnerability_cards": [],
    }


def read_evidence_payload(path):
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        return payload
    empty = _empty_evidence_payload()
    empty["vulnerability_cards"] = payload
    return empty


def update_vulnerability_cards(path, merged_cards):
    payload = read_evidence_payload(path)
    payload["vulnerability_cards"] = [{k: v for k, v in c.items() if k != "doc"} for c in merged_cards]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def clear_evidence(path):
    log.info("Clearing evidence JSON at %s", path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_empty_evidence_payload(), f, ensure_ascii=False, indent=2)


def cached_card_is_usable(card):
    if not isinstance(card, dict):
        return False
    for field in ("what_happened", "why_matters", "how_to_respond"):
        if str(localized_field(card.get(field), DEFAULT_REPORT_LANG) or "").strip():
            return True
    return bool(card.get("references") or card.get("affected_versions") or card.get("fixed_versions"))


def hydrate_cached_card(candidate, cached_card, warned=None):
    card = dict(cached_card or {})
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
    normalize_localized_fields(card, warned)
    card["doc"] = candidate["doc"]
    return card


def inspect_existing_evidence(path, candidates):
    log.info("Inspecting existing evidence from %s", path)
    try:
        payload = read_evidence_payload(path)
    except FileNotFoundError:
        log.info("Existing evidence file not found; regenerating evidence")
        return {
            "cached_cards": [],
            "missing_candidates": list(candidates),
            "search_results": [],
            "source_evidence_cards": [],
        }
    cards = payload.get("vulnerability_cards", [])
    if not cards:
        log.info("Existing evidence is empty; regenerating evidence")
        return {
            "cached_cards": [],
            "missing_candidates": list(candidates),
            "search_results": [],
            "source_evidence_cards": [],
        }
    by_id = {c["cnvd_id"]: c for c in cards if isinstance(c, dict) and c.get("cnvd_id")}
    warned = {"missing_en": False}
    cached_cards = []
    missing_candidates = []
    cached_ids = set()
    for candidate in candidates:
        cached = by_id.get(candidate["cnvd_id"])
        if cached and cached_card_is_usable(cached):
            cached_cards.append(hydrate_cached_card(candidate, cached, warned))
            cached_ids.add(candidate["cnvd_id"])
        else:
            missing_candidates.append(candidate)
    search_results = [item for item in payload.get("search_results", []) if item.get("cnvd_id") in cached_ids]
    source_evidence_cards = [item for item in payload.get("source_evidence_cards", []) if item.get("cnvd_id") in cached_ids]
    log.info(
        "Existing evidence cache: cached=%d missing=%d",
        len(cached_cards),
        len(missing_candidates),
    )
    return {
        "cached_cards": cached_cards,
        "missing_candidates": missing_candidates,
        "search_results": search_results,
        "source_evidence_cards": source_evidence_cards,
    }


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
    warned = {"missing_en": False}
    for candidate in candidates:
        merged.append(hydrate_cached_card(candidate, by_id.get(candidate["cnvd_id"]), warned))
    log.info("Loaded %d vulnerability card(s) from evidence JSON", len(merged))
    return merged
