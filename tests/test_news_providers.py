import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.dependencies import Document, load_workbook
from pipeline.docx_report import build_docx
from pipeline.evidence import hydrate_cached_card, inspect_existing_evidence, matching_evidence_cards, merge_cards, normalize_card
from pipeline.excel_report import build_weekly_excel
from pipeline.formatting import weekly_row, word_rows
from pipeline.mongo import candidate_from_news_doc, candidates_from_payload, docs_to_candidates, query_news
from pipeline.news_schema import doc_cve_ids, news_fields
from pipeline.vuln_match import build_filtered_matches, doc_fields, first_match, searchable_text


def document(provider, details, **fields):
    return {
        "_id": f"{provider}:2026-1234", "code": "2026-1234",
        "source": {"provider": provider, "detail_url": f"https://example.test/{provider}/advisory"},
        "title": "Product vulnerability", "details": details, **fields,
    }


class NewsProviderTests(unittest.TestCase):
    def test_all_catalog_providers_and_historical_sources_map_fields(self):
        # The catalog includes providers that have not published news records yet.
        cases = {
            "avd": {"description": "AVD details", "solution": "Upgrade"},
            "cnvd": {"affected_products": ["Product"], "vendor": "Vendor", "description": "Details"},
            "cnnvd": {"productName": "Product", "vendorName": "Vendor", "vulDesc": "Details", "patch": "Upgrade"},
            "cve": {"affected": [{"product": "Product", "vendor": "Vendor", "versions": [{"status": "affected"}]}], "descriptions": [{"lang": "en", "value": "Details"}]},
            "github_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "description": "Details", "vulnerabilities": [{"package": {"name": "Product"}, "first_patched_version": "2.0"}]},
            "govcert": {"alert_code": "A26-10-01", "affected_systems": ["Product"], "recommendation": "Upgrade"},
            "hkcert": {"systems_affected": ["Product"], "intro": "Details", "solutions": "Upgrade"},
            "hpe": {"bulletin_id": "HPESB1234", "supported_versions": "Product 1.0", "summary": "Details", "resolution": "Upgrade"},
            "huawei_sa": {"summary": "Details", "vul": [{"cveId": "CVE-2026-1234"}]},
            "juniper": {"products": [{"name": "Junos OS"}], "vendor": "Juniper", "description": "Details", "solution": "Upgrade"},
            "msrc": {"product_statuses": [{"type": "3", "product_names": ["Product"]}], "description": "Details", "remediations": [{"description": "Upgrade", "url": "https://vendor.test/update"}]},
            "nvd": {"affected_products": ["cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"], "description": "Details"},
            "paloalto": {"product_name": "PAN-OS", "vendor_name": "Palo Alto Networks", "summary": "Details", "remediation": "Upgrade"},
            "qianxin": {"description": {"vulnerability_information": {"product": "Product", "vendor": "Vendor", "summary": "Details"}, "recommendations": ["Upgrade"]}},
            "splunk": {"affected_products": [{"product": "Splunk Enterprise"}], "vendors": ["Splunk"], "description": "Details", "recommendations": ["Upgrade"]},
            "zimbra": {"security_fixes": ["Details"], "patch_installation_url": "https://vendor.test/update"},
            "future_provider": {"products": ["Product"], "vendor": "Vendor", "description": "Details"},
        }
        for provider, details in cases.items():
            with self.subTest(provider=provider):
                doc = document(provider, details, severity="HIGH", cve_ids=["CVE-2026-1234"])
                candidate = candidate_from_news_doc(doc)
                self.assertEqual(candidate["record_id"], doc["_id"])
                self.assertEqual(candidate["source"], provider)
                self.assertEqual(candidate["severity"], "High")
                self.assertEqual(candidate["cve_ids"], ["CVE-2026-1234"])
                self.assertEqual(candidate["references"][0], doc["source"]["detail_url"])
                for key in ("title", "summary", "solution"):
                    self.assertIsInstance(candidate[key], str)
                for key in ("vendors", "affected_products", "references"):
                    self.assertTrue(all(isinstance(value, str) for value in candidate[key]))
                if provider not in ("avd", "huawei_sa"):
                    self.assertTrue(candidate["affected_products"])
                    self.assertIn(candidate["affected_products"][0].lower(), searchable_text(provider, doc))

    def test_affected_packages_cpes_and_cvss_are_normalized(self):
        doc = document("cve", {
            "affected": [
                {"packageName": "serialize-javascript", "vendor": "Yahoo", "versions": [{"status": "affected"}]},
                {"product": "Unaffected Product", "defaultStatus": "unaffected", "versions": [{"status": "unaffected"}]},
            ],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:example_vendor:example_product:1:*:*:*:*:*:*:*"},
                {"vulnerable": False, "criteria": "cpe:2.3:o:other:unaffected:1:*:*:*:*:*:*:*"},
            ]}]}],
            "metrics": {"cvss_v31": [{"cvssData": {"baseScore": 8.8}}]},
            "descriptions": [{"lang": "en", "value": "A package issue."}],
            "references": [{"url": "https://vendor.test/security", "tags": ["Patch"]}],
        })
        candidate = candidate_from_news_doc(doc)
        self.assertEqual(candidate["affected_products"], ["serialize-javascript", "example product"])
        self.assertEqual(candidate["vendors"], ["Yahoo", "example vendor"])
        self.assertEqual(candidate["severity"], "High")
        self.assertEqual(candidate["summary"], "A package issue.")
        self.assertIn("https://vendor.test/security", candidate["references"])
        self.assertEqual(candidate["cve_id"], "CVE-2026-1234")
        future = {**doc, "_id": "new_scraper:1", "source": {"provider": "new_scraper"}}
        self.assertEqual(news_fields(future)["affected_products"], candidate["affected_products"])
        self.assertEqual(news_fields(future)["vendors"], candidate["vendors"])

    def test_qianxin_nested_text_stays_out_of_keyword_matching(self):
        doc = document("qianxin", {"description": {
            "vulnerability_information": {"product": "Next.js", "vendor": "Vercel", "summary": "Mentions Python in a comparison.", "cve_id": "CVE-2026-1234"},
            "recommendations": ["Upgrade Next.js", "Apply the mitigation"],
            "threat_assessment": {"cvss_3_1_score": "9.8"},
        }})
        fields = news_fields(doc)
        self.assertEqual(fields["affected_products"], ["Next.js"])
        self.assertEqual(fields["vendors"], ["Vercel"])
        self.assertEqual(fields["solution"], "Upgrade Next.js\nApply the mitigation")
        self.assertEqual(fields["severity"], "Critical")
        self.assertEqual(doc_cve_ids(doc), ["CVE-2026-1234"])
        self.assertIsNone(first_match([{"term": "Python"}], searchable_text("qianxin", doc)))
        self.assertEqual(doc_fields("qianxin", doc)["summary"], "Mentions Python in a comparison.")

    def test_msrc_excludes_unaffected_and_fixed_only_products(self):
        doc = document("msrc", {"product_statuses": [
            {"type": "3", "product_names": ["Affected Product"]},
            {"type": "0", "product_names": ["Unaffected Product"]},
            {"type": "2", "product_names": ["Fixed Product"]},
        ], "cvss": [{"base_score": "9.3"}]})
        candidate = candidate_from_news_doc(doc)
        self.assertEqual(candidate["affected_products"], ["Affected Product"])
        self.assertEqual(candidate["severity"], "Critical")
        self.assertEqual(candidate["cnvd_id"], "CVE-2026-1234")

    def test_future_providers_root_fields_and_missing_optional_data(self):
        doc = document("future_provider", {}, product="New Product", vendor="New Vendor", description="Root description", solution="Root remediation", references=["https://vendor.test/root"])
        candidate = candidate_from_news_doc(doc)
        self.assertEqual(candidate["affected_products"], ["New Product"])
        self.assertEqual(candidate["vendors"], ["New Vendor"])
        self.assertEqual(candidate["summary"], "Root description")
        self.assertEqual(candidate["solution"], "Root remediation")
        self.assertIn("https://vendor.test/root", candidate["references"])
        self.assertIsNone(candidate["severity"])
        self.assertEqual(candidate["cve_ids"], [])
        self.assertIsNone(candidate_from_news_doc({"_id": "unknown:1", "details": {}}))

    def test_query_all_providers_and_shortlist_do_not_assume_id_prefix(self):
        with patch("pipeline.mongo.run_mongo", return_value=[]) as mongo:
            query_news(days=7)
        script = mongo.call_args.args[0]
        self.assertIn("const providers = null;", script)
        self.assertIn('{$type: "string", $nin: [""]}', script)
        self.assertIn("observed_at: {$gte: cutoff}", script)
        self.assertIn("scraped_at: {$gte: cutoffIso}", script)
        doc = document("juniper", {"products": ["Junos OS"]}, _id="opaque-mongo-key")
        payload = {"matches": [{"record_id": doc["_id"], "source": "juniper", "id": "Advisory"}] * 2}
        with patch("pipeline.mongo.query_news", return_value=[doc]) as query:
            candidates = candidates_from_payload(payload)
        query.assert_called_once_with(record_ids=["opaque-mongo-key"])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["record_id"], "opaque-mongo-key")

    def test_filter_applies_nested_severity_and_dates_for_every_provider(self):
        docs = [
            document("github_advisory", {"vulnerabilities": [{"package": {"name": "Target"}}], "cvss_severities": {"cvss_v3": {"score": 9.1}}}),
            document("future_provider", {"product": "Target"}, severity="HIGH"),
            document("govcert", {"affected_systems": ["Target"]}),
            document("msrc", {"product_statuses": [{"type": "3", "product_names": ["Target"]}]}, severity="Low"),
        ]
        term = {"term": "Target", "term_kind": "label", "cluster_id": "T", "cluster_label": "Target", "cluster_size": 1}
        with patch("pipeline.vuln_match.software_terms", return_value=[term]), \
             patch("pipeline.vuln_match.query_news", return_value=docs) as query, \
             patch("pipeline.vuln_match.confirm_software_match", return_value={"related": True, "confidence": "high", "reason": "direct"}):
            payload, _ = build_filtered_matches({"severity_filter": ["High", "Critical"], "vuln_match_scrape_days": 7})
        query.assert_called_once_with(None, days=7)
        self.assertEqual({item["source"] for item in payload["matches"]}, {"github_advisory", "future_provider"})

    def test_same_cve_from_different_providers_keeps_separate_identity_and_cache(self):
        candidates = docs_to_candidates([document(provider, {}, cve_ids=["CVE-2026-1234"]) for provider in ("cve", "msrc", "nvd")])
        self.assertEqual(len(candidates), 3)
        evidence = [{"record_id": "msrc:2026-1234", "cnvd_id": "CVE-2026-1234", "what_happened": "Microsoft evidence"}]
        self.assertEqual(matching_evidence_cards(candidates[0], evidence), [])
        self.assertEqual(matching_evidence_cards(candidates[1], evidence), evidence)
        legacy = [{"cnvd_id": "CVE-2026-1234", "source": "msrc", "what_happened": "Microsoft evidence"}]
        self.assertEqual(matching_evidence_cards(candidates[0], legacy), [])
        self.assertEqual(matching_evidence_cards(candidates[1], legacy), legacy)
        self.assertEqual(matching_evidence_cards(candidates[0], [{"cnvd_id": "CVE-2026-1234"}]), [])

    def test_cache_and_evidence_preserve_report_fields_without_cross_provider_results(self):
        candidate = candidate_from_news_doc(document("msrc", {"vendor": "Microsoft", "product": "Windows"}, cve_ids=["CVE-2026-1234", "CVE-2026-5678"]))
        evidence = normalize_card({"what_happened": "Issue"}, {"task_type": "what_happened"}, candidate)
        merged = merge_cards([candidate], [evidence])[0]
        hydrated = hydrate_cached_card(candidate, {"what_happened": "Cached"})
        for card in (evidence, merged, hydrated):
            self.assertEqual(card["vendors"], ["Microsoft"])
            self.assertEqual(card["cve_ids"], ["CVE-2026-1234", "CVE-2026-5678"])
            self.assertEqual(card["affected_products"], ["Windows"])
        legacy = {"cnvd_id": candidate["cnvd_id"], "source": "msrc", "what_happened": "Cached"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            path.write_text(json.dumps({"vulnerability_cards": [legacy], "search_results": [legacy, {**legacy, "source": "nvd"}]}))
            state = inspect_existing_evidence(path, [candidate])
        self.assertEqual(state["missing_candidates"], [])
        self.assertEqual(state["search_results"], [legacy])

    def test_report_basic_info_is_cve_vendor_product_for_every_provider(self):
        for provider in ("cnvd", "cnnvd", "github_advisory", "juniper", "paloalto", "splunk"):
            with self.subTest(provider=provider):
                candidate = candidate_from_news_doc(document(provider, {"products": ["Product"], "vendor": "Vendor"}, cve_ids=["CVE-2026-1234", "CVE-2026-5678"]))
                card = merge_cards([candidate], [])[0]
                rows = word_rows(card, "en")
                self.assertEqual(rows[1], ("CVE number", "CVE-2026-1234\nCVE-2026-5678", "Vendor", "Vendor"))
                self.assertEqual(rows[2][3], "Product")
                self.assertEqual(weekly_row(card)[2:5], ["CVE-2026-1234\nCVE-2026-5678", "Vendor", "Product"])
        card = merge_cards([candidate_from_news_doc(document("zimbra", {}))], [])[0]
        self.assertEqual(weekly_row(card)[2:5], ["-", "-", "Zimbra"])

    def test_generated_reports_replace_legacy_template_labels(self):
        candidate = candidate_from_news_doc(document("github_advisory", {"products": ["Product"], "vendor": "Vendor"}, cve_ids=["CVE-2026-1234"]))
        card = merge_cards([candidate], [])[0]
        card["title"]["en"] = "Product issue"
        with tempfile.TemporaryDirectory() as directory:
            docx = str(Path(directory) / "report.docx")
            xlsx = str(Path(directory) / "report.xlsx")
            build_docx([card], {"docx_template": "templates/report.docx"}, "en", docx)
            build_weekly_excel([card], {"weekly_excel_template": "templates/weekly_disclosure.xlsx", "output_weekly_excel": xlsx})
            table = Document(docx).tables[0]
            self.assertEqual([cell.text for cell in table.rows[1].cells], ["CVE number", "CVE-2026-1234", "Vendor", "Vendor"])
            self.assertEqual(table.rows[2].cells[3].text, "Product")
            ws = load_workbook(xlsx).active
            self.assertEqual([ws.cell(2, col).value for col in range(3, 6)], ["CVE编号", "厂商", "影响产品"])
            self.assertEqual([ws.cell(3, col).value for col in range(3, 6)], ["CVE-2026-1234", "Vendor", "Product"])


if __name__ == "__main__":
    unittest.main()
