from pipeline.constants import DEFAULT_REPORT_LANG, LOCALES
from pipeline.utils import one_line, val


def localized(card, field, lang):
    value = card.get(field)
    if isinstance(value, dict):
        return value.get(lang) or ""
    return value if lang == DEFAULT_REPORT_LANG else ""


def card_raw(card):
    return card["doc"].get("details", {}).get(card.get("source", "cnvd"), {})


def card_date(card):
    raw = card_raw(card)
    return raw.get("published_date") or raw.get("publishDate") or card["doc"].get("disclosure_date") or card["doc"].get("published_time")


def format_severity(value, lang):
    text = val(value)
    return LOCALES["zh"]["severity_map"].get(text, text) if lang == "zh" else text


def link_for(card):
    return f"https://nvd.nist.gov/vuln/detail/{card['cve_id']}" if card.get("cve_id") else (card.get("references") or ["-"])[0]


def category(card):
    text = " ".join([localized(card, "title", DEFAULT_REPORT_LANG), localized(card, "what_happened", DEFAULT_REPORT_LANG)]).lower()
    checks = [
        ("代码执行", ("代码执行", "任意代码", "code execution", "rce")),
        ("信息泄露", ("信息泄露", "敏感信息", "information disclosure", "leak")),
        ("权限提升", ("权限", "privilege escalation")),
        ("SQL注入", ("sql", "注入")),
        ("XSS", ("xss", "cross site scripting", "跨站")),
    ]
    for label, needles in checks:
        if any(n.lower() in text for n in needles):
            return label
    return "其他"


def product_text(card):
    return val(card.get("affected_products"))


def asset_text(card):
    return val(card.get("cluster_label") or card.get("matched_software"))


def word_rows(card, lang):
    labels = LOCALES[lang]["labels"]
    id_label = "CNNVD编号" if card.get("source") == "cnnvd" and lang == "zh" else ("CNNVD Number" if card.get("source") == "cnnvd" else labels["cnvd"])
    products = card.get("affected_products") or []
    what_happened = localized(card, "what_happened", lang)
    why_matters = localized(card, "why_matters", lang)
    hazard = what_happened or "-"
    if why_matters:
        hazard += "\n" + why_matters
    return [
        (labels["title"] + val(localized(card, "title", lang)),),
        (labels["cve"], card.get("cve_id") or "-", id_label, card["cnvd_id"]),
        (labels["system"], asset_text(card), labels["product"], one_line(products)),
        (labels["threat"], format_severity(card.get("severity") or card_raw(card).get("severity"), lang), labels["date"], val(card_date(card))),
        (labels["hazard"] + hazard,),
        (labels["scope"] + val(products),),
        (labels["ref"] + ((card.get("references") or ["-"])[0]),),
        (labels["patch"] + val(localized(card, "how_to_respond", lang)),),
        (labels["link"] + link_for(card),),
    ]


def weekly_row(card):
    return ["", "", card.get("cve_id") or "-", card["cnvd_id"], product_text(card), localized(card, "title", DEFAULT_REPORT_LANG), format_severity(card.get("severity") or card_raw(card).get("severity"), DEFAULT_REPORT_LANG)]
