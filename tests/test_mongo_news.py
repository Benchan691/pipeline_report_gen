import unittest
from unittest.mock import patch

from pipeline.mongo import (
    candidates_from_payload,
    docs_to_candidates,
    query_cnvd,
    query_cnvd_by_scrape_days,
    query_news,
)


def cnvd_doc():
    return {
        "_id": "cnvd:2026-75604",
        "schema_version": 2,
        "code": "2026-75604",
        "title": "Next.js cache path traversal",
        "severity": "High",
        "cve_ids": ["CVE-2026-75604"],
        "source": {
            "provider": "cnvd",
            "detail_url": "https://cnvd.example/detail/CNVD-2026-75604",
        },
        "details": {
            "description": "Path traversal in the incremental cache.",
            "affected_products": ["Next.js"],
            "solution": "Upgrade to the fixed release.",
            "reference_links": ["https://vendor.example/advisory"],
        },
    }


def cnnvd_doc():
    return {
        "_id": "cnnvd:2026-39774431",
        "schema_version": 2,
        "code": "2026-39774431",
        "title": "CNNVD sample vulnerability",
        "severity": "高危",
        "cve_ids": ["CVE-2026-39774431"],
        "source": {
            "provider": "cnnvd",
            "detail_url": "https://cnnvd.example/detail/CNNVD-2026-39774431",
        },
        "details": {
            "cnnvdId": "CNNVD-2026-39774431",
            "vulName": "CNNVD sample vulnerability",
            "vulLevel": "高危",
            "vulDesc": "A product vulnerability description.",
            "vendorName": "Example Vendor",
            "productName": "Example Product",
            "fixStatus": "Install the released patch.",
            "officialPatchLink": "https://vendor.example/patch",
        },
    }


class MongoUnifiedNewsTests(unittest.TestCase):
    def test_provider_mapping_uses_news_schema_and_skips_other_sources(self):
        avd_doc = {
            "_id": "avd:2026-75604",
            "source": {"provider": "avd"},
            "title": "Same CVE from AVD",
        }

        candidates = docs_to_candidates([avd_doc, cnvd_doc(), cnnvd_doc()])

        self.assertEqual([candidate["source"] for candidate in candidates], ["cnvd", "cnnvd"])
        cnvd = candidates[0]
        self.assertEqual(cnvd["record_id"], "cnvd:2026-75604")
        self.assertEqual(cnvd["candidate_id"], "cnvd:2026-75604")
        self.assertEqual(cnvd["cnvd_id"], "CNVD-2026-75604")
        self.assertEqual(cnvd["cve_id"], "CVE-2026-75604")
        self.assertEqual(cnvd["affected_products"], ["Next.js"])
        self.assertEqual(cnvd["severity"], "High")
        self.assertEqual(cnvd["references"], ["https://cnvd.example/detail/CNVD-2026-75604"])
        self.assertEqual(cnvd["solution"], "Upgrade to the fixed release.")

        cnnvd = candidates[1]
        self.assertEqual(cnnvd["record_id"], "cnnvd:2026-39774431")
        self.assertEqual(cnnvd["source"], "cnnvd")
        self.assertEqual(cnnvd["cnvd_id"], "CNNVD-2026-39774431")
        self.assertEqual(cnnvd["affected_products"], ["Example Vendor", "Example Product"])
        self.assertEqual(cnnvd["severity"], "高危")
        self.assertEqual(cnnvd["references"], ["https://cnnvd.example/detail/CNNVD-2026-39774431"])
        self.assertEqual(cnnvd["solution"], "Install the released patch.")

    def test_query_targets_news_filters_providers_and_keeps_date_window(self):
        with patch("pipeline.mongo.run_mongo", return_value=[]) as run_mongo:
            query_news(
                ("cnvd", "cnnvd", "avd"),
                days=7,
                record_ids=["cnvd:2026-75604", "cnnvd:2026-39774431"],
            )

        script = run_mongo.call_args.args[0]
        self.assertIn(".news.find(query", script)
        self.assertIn('const providers = ["cnnvd", "cnvd"];', script)
        self.assertIn('const query = {"source.provider": {$in: providers}};', script)
        self.assertIn('const recordIds = ["cnvd:2026-75604", "cnnvd:2026-39774431"];', script)
        self.assertIn("query._id = {$in: recordIds};", script)
        self.assertIn("query.$or = [{observed_at: {$gte: cutoff}}, {scraped_at: {$gte: cutoffIso}}]", script)
        self.assertNotIn(".cnvd.find", script)
        self.assertNotIn(".cnnvd.find", script)
        self.assertNotIn("avd", script)
        self.assertRegex(script, r'const cutoffMs = "\d+";')

    def test_plain_scrape_days_and_explicit_ids_remain_cnvd_only(self):
        with patch("pipeline.mongo.run_mongo", return_value=[cnvd_doc()]) as run_mongo:
            candidates = query_cnvd_by_scrape_days(7)
        self.assertEqual([candidate["source"] for candidate in candidates], ["cnvd"])
        scrape_script = run_mongo.call_args.args[0]
        self.assertIn('const providers = ["cnvd"];', scrape_script)
        self.assertIn("query.$or =", scrape_script)

        with patch("pipeline.mongo.run_mongo", return_value=[cnvd_doc()]) as run_mongo:
            candidates = query_cnvd(["CNVD-2026-75604"])
        self.assertEqual([candidate["record_id"] for candidate in candidates], ["cnvd:2026-75604"])
        explicit_script = run_mongo.call_args.args[0]
        self.assertIn('const providers = ["cnvd"];', explicit_script)
        self.assertIn('const recordIds = ["cnvd:2026-75604"];', explicit_script)
        self.assertIn("query._id = {$in: recordIds};", explicit_script)
        self.assertIn('const cutoffMs = "";', explicit_script)

    def test_cluster_payload_refetches_by_canonical_id_and_ignores_other_provider(self):
        docs = [cnvd_doc(), cnnvd_doc(), {
            "_id": "avd:2026-75604",
            "code": "2026-75604",
            "source": {"provider": "avd"},
            "title": "AVD duplicate",
        }]
        payload = {
            "matches": [
                {"record_id": "cnnvd:2026-39774431", "source": "cnnvd", "id": "CNNVD-2026-39774431", "mark": 12},
                {"record_id": "cnvd:2026-75604", "source": "cnvd", "id": "CNVD-2026-75604", "mark": 10},
                {"record_id": "avd:2026-75604", "source": "avd", "id": "AVD-2026-75604"},
            ],
        }

        with patch("pipeline.mongo.run_mongo", return_value=docs) as run_mongo:
            candidates = candidates_from_payload(payload)

        self.assertEqual([candidate["record_id"] for candidate in candidates], [
            "cnnvd:2026-39774431", "cnvd:2026-75604",
        ])
        self.assertEqual([candidate["cnvd_id"] for candidate in candidates], [
            "CNNVD-2026-39774431", "CNVD-2026-75604",
        ])
        script = run_mongo.call_args.args[0]
        self.assertIn(".news.find(query", script)
        self.assertIn('const providers = ["cnnvd", "cnvd"];', script)
        self.assertIn('const recordIds = ["cnnvd:2026-39774431", "cnvd:2026-75604"];', script)
        self.assertIn("query._id = {$in: recordIds};", script)
        self.assertNotIn(".cnvd.find", script)
        self.assertNotIn(".cnnvd.find", script)


if __name__ == "__main__":
    unittest.main()
