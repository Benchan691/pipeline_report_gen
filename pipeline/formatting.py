import re

from pipeline.constants import LOCALES
from pipeline.utils import one_line, unique, val


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
    text = " ".join([card.get("title", ""), card.get("what_happened", "")]).lower()
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


def affected_version_text(card):
    versions = card.get("affected_versions") or []
    if versions:
        return val(versions)
    text = product_text(card)
    matches = re.findall(r"\b(?:v(?:ersion)?\s*)?\d+(?:\.\d+){0,3}\b", text, re.I)
    return "\n".join(unique(matches)) or "-"


def excel_row(card):
    return [asset_text(card), product_text(card), affected_version_text(card), card.get("cve_id") or card["cnvd_id"], card.get("title"), category(card), card.get("what_happened"), card.get("how_to_respond")]


def word_rows(card, lang):
    labels = LOCALES[lang]["labels"]
    id_label = "CNNVD编号" if card.get("source") == "cnnvd" and lang == "zh" else ("CNNVD Number" if card.get("source") == "cnnvd" else labels["cnvd"])
    products = card.get("affected_products") or []
    hazard = card.get("what_happened") or "-"
    if card.get("why_matters"):
        hazard += "\n" + card["why_matters"]
    return [
        (labels["title"] + val(card.get("title")),),
        (labels["cve"], card.get("cve_id") or "-", id_label, card["cnvd_id"]),
        (labels["system"], asset_text(card), labels["product"], one_line(products)),
        (labels["threat"], format_severity(card.get("severity") or card_raw(card).get("severity"), lang), labels["date"], val(card_date(card))),
        (labels["hazard"] + hazard,),
        (labels["scope"] + val(products),),
        (labels["ref"] + ((card.get("references") or ["-"])[0]),),
        (labels["patch"] + val(card.get("how_to_respond")),),
        (labels["link"] + link_for(card),),
    ]


def weekly_row(card):
    return ["", "", card.get("cve_id") or "-", card["cnvd_id"], product_text(card), card.get("title"), format_severity(card.get("severity") or card_raw(card).get("severity"), "zh")]
