# CNVD Evidence-Card DOCX + XLSX Generator

Pipeline:

1. Match CNVD/CNNVD records against installed-software clusters and pass the ranked shortlist directly to search when `use_filtered_vuln_ids` is true.
2. Load matched records from local MongoDB.
3. Search SearXNG or Firecrawl by related CVE, or by CNVD ID when no CVE exists.
4. Extract evidence cards with llama-server.
5. Save `cnvd_evidence_cards.json`.
6. Fill the Word and Excel templates and email the outputs.

Templates live in `templates/`. Each run writes four files based on the basename paths in `config.json` (for example `周報.docx`, `周報_en.docx`, `周報.xlsx`, `本周重要漏洞实例情况.xlsx`). When `output_date_prefix` is true (default), filenames are auto-prefixed with the report publish-date range, e.g. `2026.06.30-07.06_周報.docx` and `2026.06.30-07.06_周報_en.docx`.

Languages are hardcoded in the pipeline: Chinese and English DOCX files are always generated, Chinese evidence is extracted first, and the merged report text is then translated to English. Excel outputs remain Chinese.

`report.xlsx` keeps `影响资产` empty and fills `影响产品` / `影响版本` from CNVD plus AI evidence. `weekly_disclosure.xlsx` leaves `是否涉及` empty for human review.

## Requirements

- `mongosh` in `PATH`
- SearXNG JSON search API, default `http://localhost:8086`
- Firecrawl API key when using Firecrawl or SearXNG fallback
- llama-server, default `http://100.102.169.17:8080`
- Python with `python-docx` and `openpyxl`

```bash
PY=/Users/chankokpan/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3
$PY cnvd_docx.py --self-test
```

## Config

Edit `config.json` (copy from [`config.example.json`](config.example.json)):

```json
{
  "scrape_days": 7,
  "search_provider": "searxng",
  "searxng_base_url": "http://localhost:8086",
  "firecrawl_api_key": "fc-...",
  "evidence_json": "cnvd_evidence_cards.json",
  "output_docx": "report.docx",
  "output_excel": "report.xlsx",
  "output_weekly_excel": "weekly_disclosure.xlsx",
  "email_title": "報告",
  "email_body": "附件為本周報告。"
}
```

Set `"search_provider": "firecrawl"` to use Firecrawl directly. With SearXNG as the provider, Firecrawl is used as a fallback when SearXNG returns no usable results and `firecrawl_api_key` is configured.

`scrape_days` loads every CNVD in MongoDB whose `scraped_at` falls within the last N days. You can still pass an explicit `cnvd_ids` list instead to override the window query.

To regenerate reports from an existing evidence JSON without new web/AI extraction:

```json
"use_existing_evidence_json": true
```

## Usage

One command runs the full workflow (cluster matching + report generation):

```bash
.venv/bin/python cnvd_docx.py --config config.json
```

Optional funnel debug dump:

```bash
python3 export_vuln_funnel_details.py --config config.json
```

Outputs are written to dated paths derived from `config.json` (e.g. `2026.06.30-07.06_周報.docx` and `2026.06.30-07.06_周報_en.docx`).

To email report files from an existing run folder under `output_root`:

```bash
.venv/bin/python cnvd_docx.py --config config.json --send-email 20260706_173000
```

This attaches every `.docx` and `.xlsx` file in that folder. You can also pass an absolute path or a path already under `output/`.

Email subject is built as `日期範圍 + email_title`, for example `2026年5月20日-5月26日報告`.

## Layout

- [`cnvd_docx.py`](cnvd_docx.py) — CLI entry point
- [`pipeline/cli.py`](pipeline/cli.py) — orchestration and self-test
- [`pipeline/vuln_match.py`](pipeline/vuln_match.py) — software-cluster matching and shortlist
- [`pipeline/mongo.py`](pipeline/mongo.py) — MongoDB queries and candidates
- [`pipeline/search.py`](pipeline/search.py) — SearXNG / Firecrawl search
- [`pipeline/evidence.py`](pipeline/evidence.py) — AI extraction and evidence JSON
- [`pipeline/formatting.py`](pipeline/formatting.py) — card text helpers for reports
- [`pipeline/output.py`](pipeline/output.py) — dated output paths and title dates
- [`pipeline/docx_report.py`](pipeline/docx_report.py) — Word report builder
- [`pipeline/excel_report.py`](pipeline/excel_report.py) — Excel report builders
