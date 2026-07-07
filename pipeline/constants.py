DB = "vulnerabilities"
DEFAULT_CONFIG = "config.json"
REPORT_LANGS = ("zh", "en")
DEFAULT_REPORT_LANG = "zh"
CONFIDENCE = {"high": 3, "medium": 2, "low": 1}
TASK_TYPES = ("what_happened", "why_matters", "how_to_respond")
EVIDENCE_KEYS = [
    "cnvd_id",
    "cve_id",
    "search_id",
    "title",
    "what_happened",
    "why_matters",
    "how_to_respond",
    "affected_versions",
    "fixed_versions",
    "cvss_score",
    "cvss_vector",
    "references",
    "confidence",
]
LOCALES = {
    "zh": {
        "title_fallback": "%Y年%m.%d最新漏洞情报",
        "title_range": "{y1}年{m1}.{d1}-{m2}.{d2}最新漏洞情报",
        "labels": {
            "title": "标题：",
            "cve": "CVE编号",
            "cnvd": "CNVD编号",
            "system": "受影响系统",
            "product": "影响产品",
            "threat": "威胁级别",
            "date": "发布日期",
            "hazard": "漏洞危害：",
            "scope": "影响范围:",
            "ref": "参考网址：",
            "patch": "官方补丁：",
            "link": "漏洞链接：",
        },
        "severity_map": {"Critical": "严重", "High": "高危", "Medium": "中危", "Low": "低危", "Critical-risk": "严重", "High-risk": "高危", "Medium-risk": "中危", "Low-risk": "低危"},
    },
    "en": {
        "title_fallback": "%Y\u2002%m.%d\u2002Latest\u2002vulnerability\u2002intelligence",
        "title_range": "{y1}\u2002{m1}.{d1}-{m2}.{d2}\u2002Latest\u2002vulnerability\u2002intelligence",
        "labels": {
            "title": "Title: ",
            "cve": "CVE number",
            "cnvd": "CNVD Number",
            "system": "Affected system",
            "product": "Affect the product",
            "threat": "Threat level",
            "date": "Release date",
            "hazard": "Vulnerability hazard: ",
            "scope": "Scope of impact: ",
            "ref": "Reference site: ",
            "patch": "The official patch: ",
            "link": "Hole link: ",
        },
        "scope_alt_prefix": "Affected scope:",
    },
}
