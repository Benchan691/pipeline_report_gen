import json
import unittest
from unittest.mock import call, patch

from pipeline.vuln_match import (
    cap_per_cluster,
    build_filtered_matches,
    clean_term,
    confirm_software_match,
    first_match,
    match_confirmation_prompt,
    norm_id,
    norm_severity,
    ranked_matches,
    searchable_text,
)


class VulnerabilityMatchTests(unittest.TestCase):
    def test_normalizes_terms_ids_and_severity(self):
        self.assertEqual(clean_term("Java 8 Update 202 (64-bit)"), "Java")
        self.assertEqual(norm_id("cnvd", "2026-24916"), "CNVD-2026-24916")
        self.assertEqual(norm_severity("中\n(AV:L)"), "Medium")

    def test_does_not_match_language_mentions_as_software(self):
        document = {"title": "Conductor vulnerability", "details": {"cnnvd": {"vulDesc": "An inline JavaScript or Python expression is evaluated.", "productName": "Conductor"}}}
        self.assertIsNone(first_match([{"term": "Python"}, {"term": "Java"}], searchable_text("cnnvd", document)))

    def test_ranking_and_cluster_cap_prioritize_highest_scored_items(self):
        items = [
            {"id": "C1", "cluster_id": "chrome", "severity": "Critical", "mark": 10},
            {"id": "C2", "cluster_id": "chrome", "severity": "High", "mark": 9},
            {"id": "J1", "cluster_id": "java", "severity": "High", "mark": 8},
        ]
        self.assertEqual([item["id"] for item in cap_per_cluster(items, 1)], ["C1", "J1"])
        self.assertEqual([item["id"] for item in ranked_matches(items, 2)], ["C1", "C2"])

    def test_confirmation_respects_configured_thinking_and_uses_response(self):
        document = {"code": "CNNVD-1", "title": "Google Chrome vulnerability", "details": {"cnnvd": {"vulName": "Google Chrome vulnerability", "productName": "Google Chrome"}}}
        match = {"term": "Google Chrome", "cluster_label": "Google Chrome", "cluster_id": "C1", "cluster_size": 1, "term_kind": "label"}
        answer = json.dumps({"related": True, "confidence": "high", "reason": "direct match"})
        for setting, expected in ((None, True), (True, True), (False, False)):
            with self.subTest(thinking=setting):
                cfg = {"ai_base_url": "http://test", "ai_model": "test", "vuln_match_ai_max_tokens": 123, "vuln_match_thinking_budget_tokens": 45}
                if setting is not None:
                    cfg["vuln_match_enable_thinking"] = setting
                content = "<think>Product relationship checked.</think>\n" + answer if expected else answer
                body = json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")
                with patch("pipeline.evidence.urllib.request.urlopen") as urlopen:
                    urlopen.return_value.__enter__.return_value.read.return_value = body
                    result = confirm_software_match(document, "cnnvd", match, cfg)

                payload = json.loads(urlopen.call_args.args[0].data)
                self.assertEqual(result, {"related": True, "confidence": "high", "reason": "direct match"})
                self.assertEqual(payload["max_tokens"], 123)
                self.assertEqual(payload["chat_template_kwargs"], {"enable_thinking": expected})
                if expected:
                    self.assertEqual(payload["thinking_budget_tokens"], 45)
                else:
                    self.assertNotIn("thinking_budget_tokens", payload)

    def test_confirmation_prompt_carries_canonical_id_and_display_id(self):
        document = {
            "_id": "cnnvd:2026-1000",
            "code": "2026-1000",
            "source": {"provider": "cnnvd"},
            "title": "Google Chrome vulnerability",
            "details": {"productName": "Google Chrome"},
        }

        _, user = match_confirmation_prompt(document, "cnnvd", {"term": "Google Chrome"})

        parsed = json.loads(user)
        self.assertEqual(parsed["vuln_id"], "CNNVD-2026-1000")
        self.assertEqual(parsed["record_id"], "cnnvd:2026-1000")

    def test_confirmation_prompt_defaults_ambiguous_and_indirect_matches_to_false(self):
        document = {"code": "CNNVD-1", "details": {"cnnvd": {"vulName": "SDK vulnerability", "productName": "Snowflake Snowpark Python SDK"}}}
        match = {"term": "Python", "cluster_label": "Python"}

        system, user = match_confirmation_prompt(document, "cnnvd", match)

        self.assertIn("keyword match is an untrusted", system)
        self.assertIn("when evidence is missing, ambiguous, indirect, or conflicting, return related=false", system)
        self.assertIn("A medium- or low-confidence relationship must be related=false", system)
        self.assertIn("plugins, connectors, integrations", system)
        self.assertEqual(json.loads(user)["product"], "Snowflake Snowpark Python SDK")

    def test_confirmation_rejects_non_boolean_or_unavailable_responses(self):
        document = {"code": "CNNVD-1", "details": {"cnnvd": {}}}
        match = {"term": "Chrome", "cluster_label": "Chrome"}
        cfg = {"ai_base_url": "http://test", "ai_model": "test"}
        with patch("pipeline.evidence.call_ai", return_value=json.dumps({"related": "false"})):
            self.assertFalse(confirm_software_match(document, "cnnvd", match, cfg)["related"])
        with patch("pipeline.evidence.call_ai", return_value="not json"):
            self.assertFalse(confirm_software_match(document, "cnnvd", match, cfg)["related"])
        with patch("pipeline.evidence.call_ai", side_effect=SystemExit("offline")):
            self.assertEqual(confirm_software_match(document, "cnnvd", match, cfg)["reason"], "llm_unavailable")

    def test_post_selection_verification_backfills_and_respects_cluster_cap(self):
        terms = [
            {"term": "Chrome", "term_kind": "label", "cluster_id": "chrome", "cluster_label": "Chrome", "cluster_size": 1},
            {"term": "Java", "term_kind": "label", "cluster_id": "java", "cluster_label": "Java", "cluster_size": 1},
        ]
        docs = [
            {"code": "1", "title": "Chrome critical", "severity": "Critical", "source": {"provider": "cnvd"}, "details": {"cnvd": {}}},
            {"code": "2", "title": "Chrome high", "severity": "High", "source": {"provider": "cnvd"}, "details": {"cnvd": {}}},
            {"code": "3", "title": "Java high", "severity": "High", "source": {"provider": "cnvd"}, "details": {"cnvd": {}}},
            {"code": "4", "title": "Java medium", "severity": "Medium", "source": {"provider": "cnvd"}, "details": {"cnvd": {}}},
        ]
        cfg = {"vuln_match_top_n": 3, "vuln_match_max_per_cluster": 1}

        with patch("pipeline.vuln_match.software_terms", return_value=terms), \
             patch("pipeline.vuln_match.docs_for", return_value=docs), \
             patch("pipeline.vuln_match.confirm_software_match", side_effect=[
                 {"related": False, "confidence": "low", "reason": "wrong product"},
                 {"related": True, "confidence": "high", "reason": "direct"},
                 {"related": True, "confidence": "high", "reason": "direct"},
             ]) as confirm:
            payload, stats = build_filtered_matches(cfg)

        self.assertEqual([item["id"] for item in payload["matches"]], ["CNVD-2", "CNVD-3"])
        self.assertEqual(confirm.call_count, 3)
        self.assertEqual(stats["llm_rejected"], 1)
        self.assertEqual(stats["cluster_cap_skipped"], 1)
        self.assertEqual(stats["shortfall"], 1)

    def test_post_selection_stops_verifying_once_full(self):
        term = {"term": "Chrome", "term_kind": "label", "cluster_id": "chrome", "cluster_label": "Chrome", "cluster_size": 1}
        docs = [
            {"code": str(index), "title": f"Chrome {index}", "severity": "High", "source": {"provider": "cnvd"}, "details": {"cnvd": {}}}
            for index in range(1, 5)
        ]
        cfg = {"vuln_match_top_n": 2, "vuln_match_max_rejected": 3}
        accepted = {"related": True, "confidence": "high", "reason": "direct"}
        rejected = {"related": False, "confidence": "high", "reason": "wrong product"}

        with patch("pipeline.vuln_match.software_terms", return_value=[term]), \
             patch("pipeline.vuln_match.docs_for", return_value=docs), \
             patch("pipeline.vuln_match.confirm_software_match", side_effect=[rejected, accepted, accepted, accepted]) as confirm:
            payload, stats = build_filtered_matches(cfg)

        self.assertEqual([item["id"] for item in payload["matches"]], ["CNVD-2", "CNVD-3"])
        self.assertEqual(confirm.call_count, 3)
        self.assertEqual(stats["llm_rejected"], 1)
        self.assertFalse(stats["rejection_limit_reached"])

    def test_rejection_limit_stops_confirmation_and_keeps_accepted_matches(self):
        terms = [
            {"term": label, "term_kind": "label", "cluster_id": label.lower(), "cluster_label": label, "cluster_size": 1}
            for label in ("Chrome", "Java", "Firefox")
        ]
        docs = [
            {"code": "5", "title": "Firefox medium", "severity": "Medium", "source": {"provider": "cnvd"}, "details": {}},
            {"code": "4", "title": "Java high", "severity": "High", "source": {"provider": "cnvd"}, "details": {}},
            {"code": "3", "title": "Java high", "severity": "High", "source": {"provider": "cnvd"}, "details": {}},
            {"code": "2", "title": "Chrome high", "severity": "High", "source": {"provider": "cnvd"}, "details": {}},
            {"code": "1", "title": "Chrome critical", "severity": "Critical", "source": {"provider": "cnvd"}, "details": {}},
        ]
        cfg = {"vuln_match_top_n": 3, "vuln_match_max_rejected": 2, "vuln_match_max_per_cluster": 1}
        accepted = {"related": True, "confidence": "high", "reason": "direct"}
        rejected = {"related": False, "confidence": "high", "reason": "wrong product"}

        with patch("pipeline.vuln_match.software_terms", return_value=terms), \
             patch("pipeline.vuln_match.docs_for", return_value=docs), \
             patch("pipeline.vuln_match.confirm_software_match", side_effect=[accepted, rejected, rejected, accepted]) as confirm:
            payload, stats = build_filtered_matches(cfg)

        self.assertEqual([item["id"] for item in payload["matches"]], ["CNVD-1"])
        self.assertEqual([entry.args[0]["code"] for entry in confirm.call_args_list], ["1", "3", "4"])
        self.assertEqual(stats["llm_rejected"], 2)
        self.assertEqual(stats["cluster_cap_skipped"], 1)
        self.assertEqual(stats["shortfall"], 2)
        self.assertTrue(stats["rejection_limit_reached"])

    def test_zero_or_missing_rejection_limit_keeps_checking_until_accepted(self):
        term = {"term": "Chrome", "term_kind": "label", "cluster_id": "chrome", "cluster_label": "Chrome", "cluster_size": 1}
        docs = [
            {"code": str(index), "title": "Chrome high", "severity": "High", "source": {"provider": "cnvd"}, "details": {}}
            for index in range(1, 5)
        ]
        accepted = {"related": True, "confidence": "high", "reason": "direct"}
        rejected = {"related": False, "confidence": "high", "reason": "wrong product"}
        for setting in (None, 0):
            with self.subTest(max_rejected=setting):
                cfg = {"vuln_match_top_n": 1}
                if setting is not None:
                    cfg["vuln_match_max_rejected"] = setting
                with patch("pipeline.vuln_match.software_terms", return_value=[term]), \
                     patch("pipeline.vuln_match.docs_for", return_value=docs), \
                     patch("pipeline.vuln_match.confirm_software_match", side_effect=[rejected, rejected, accepted, accepted]) as confirm:
                    payload, stats = build_filtered_matches(cfg)

                self.assertEqual([item["id"] for item in payload["matches"]], ["CNVD-3"])
                self.assertEqual(confirm.call_count, 3)
                self.assertEqual(stats["llm_rejected"], 2)
                self.assertFalse(stats["rejection_limit_reached"])

    def test_negative_rejection_limit_fails_before_loading_vulnerabilities(self):
        with patch("pipeline.vuln_match.software_terms", return_value=[]), \
             patch("pipeline.vuln_match.docs_for") as query:
            with self.assertRaisesRegex(ValueError, "vuln_match_max_rejected must be"):
                build_filtered_matches({"vuln_match_max_rejected": -1})

        query.assert_not_called()

    def test_cluster_scan_reads_all_providers_and_keeps_mongo_ids(self):
        terms = [
            {"term": "Chrome", "term_kind": "label", "cluster_id": "chrome", "cluster_label": "Chrome", "cluster_size": 1},
            {"term": "Firefox", "term_kind": "label", "cluster_id": "firefox", "cluster_label": "Firefox", "cluster_size": 1},
        ]
        cnvd = {
            "_id": "cnvd:2026-1",
            "code": "2026-1",
            "source": {"provider": "cnvd"},
            "title": "Chrome vulnerability",
            "severity": "High",
            "details": {"affected_products": ["Chrome"]},
        }
        cnnvd = {
            "_id": "cnnvd:2026-2",
            "code": "2026-2",
            "source": {"provider": "cnnvd"},
            "title": "Firefox vulnerability",
            "severity": "High",
            "details": {"productName": "Firefox"},
        }
        unrelated = {
            "_id": "avd:2026-3",
            "code": "2026-3",
            "source": {"provider": "avd"},
            "title": "Chrome vulnerability from AVD",
            "severity": "Critical",
        }
        accepted = {"related": True, "confidence": "high", "reason": "direct product match"}

        with patch("pipeline.vuln_match.software_terms", return_value=terms), \
             patch("pipeline.vuln_match.docs_for", return_value=[cnvd, cnnvd, unrelated, {"title": "Chrome", "severity": "High"}]) as query, \
             patch("pipeline.vuln_match.confirm_software_match", return_value=accepted):
            payload, _ = build_filtered_matches({"vuln_match_top_n": 5})

        self.assertEqual(query.call_args_list, [call(None, None)])
        self.assertEqual({item["record_id"] for item in payload["matches"]}, {
            "cnvd:2026-1", "cnnvd:2026-2", "avd:2026-3",
        })
        self.assertEqual({item["id"] for item in payload["matches"]}, {"CNVD-2026-1", "CNNVD-2026-2", "AVD-2026-3"})
