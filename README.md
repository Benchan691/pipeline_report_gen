# CNVD Evidence-Card DOCX + XLSX Generator

Pipeline:

1. Match CNVD/CNNVD records against installed-software clusters and pass the ranked shortlist directly to search when `use_filtered_vuln_ids` is true.
2. Load matched records from local MongoDB.
3. Search SearXNG or Firecrawl by related CVE, or by CNVD ID when no CVE exists.
4. Extract evidence cards with llama-server.
5. Save `cnvd_evidence_cards.json`.
6. Fill the Word and Excel templates, upload the output folder to eDrive, and email the share link.

Templates live in `templates/`. Each run writes three files based on the basename paths in `config.json` (for example `周報.docx`, `周報_en.docx`, `本周重要漏洞实例情况.xlsx`). When `output_date_prefix` is true (default), filenames are auto-prefixed with the report publish-date range, e.g. `2026.06.30-07.06_周報.docx` and `2026.06.30-07.06_周報_en.docx`.

Languages are hardcoded in the pipeline: Chinese and English DOCX files are always generated, Chinese evidence is extracted first, and the merged report text is then translated to English. Excel outputs remain Chinese.

`weekly_disclosure.xlsx` leaves `是否涉及` empty for human review.

## Requirements

- `mongosh` in `PATH`
- SearXNG JSON search API, default `http://localhost:8086`
- Firecrawl API key when using Firecrawl or SearXNG fallback
- llama-server, default `http://100.102.169.17:8080`
- Python with `python-docx`, `openpyxl`, and `python-dotenv`
- Local [`edrive`](edrive) and [`zimbra`](plugin/zimbra) packages (installed via `requirements.txt`)

```bash
pip install -r requirements.txt
PY=/Users/chankokpan/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3
$PY cnvd_docx.py --self-test
```

## Config

Edit [`config.json`](config.json) for pipeline settings (search, AI, output paths, etc.).

Email title and body now live in root [`config.json`](config.json):

```json
{
  "email_title": "漏洞報告文件",
  "email_body": "各位好：\n本週漏洞報告連結如下，敬請查閱。\n..."
}
```

Example `config.json` fields:

```json
{
  "email_title": "漏洞報告文件",
  "email_body": "各位好：\n本週漏洞報告連結如下，敬請查閱。\n...",
  "scrape_days": 7,
  "search_provider": "searxng",
  "searxng_base_url": "http://localhost:8086",
  "evidence_json": "cnvd_evidence_cards.json",
  "output_docx": "report.docx",
  "output_weekly_excel": "weekly_disclosure.xlsx"
}
```

## Environment (`.env`)

Copy [`.env.example`](.env.example) to `.env` and set:

- `FIRECRAWL_API_KEY` — Firecrawl API key (required when `search_provider` is `firecrawl`, or when SearXNG fallback is enabled)
- `EMAIL_RECEIVER` — recipient email address for the final eDrive share-link notification
- `ZIMBRA_HOST`, `ZIMBRA_EMAIL`, `ZIMBRA_PASSWORD` — Zimbra SOAP account for transfer emails and notification delivery
- `EDRIVE_USERNAME` — eDrive account
- `EDRIVE_PASSWORD` — eDrive password
- `EDRIVE_REMOTE_PATH` — parent folder on eDrive (each run uploads to `{EDRIVE_REMOTE_PATH}/{run_folder}`)
- `EDRIVE_BASE_URL` — eDrive server URL (e.g. `https://edrive.citictel-cpc.com`)

After report generation, the default pipeline emails the timestamped output folder zip to Zimbra with subject `PIPELINE_UPLOAD:<folder>`. On the eDrive machine, run:

```bash
.venv/bin/python cnvd_docx.py --config config.json --receive-transfer
```

The receiver checks the latest 10 messages in Inbox folder id `2`, downloads the matching zip, uploads to eDrive, emails the eDrive share link to `EMAIL_RECEIVER`, then deletes the transfer email.

`--build-reports` uploads when `.env` is configured but does not send email. Upload is skipped with a log message when eDrive credentials are missing.

Set `"search_provider": "firecrawl"` to use Firecrawl directly. With SearXNG as the provider, Firecrawl is used as a fallback when SearXNG returns no usable results and `FIRECRAWL_API_KEY` is set in `.env`.

`scrape_days` loads every CNVD in MongoDB whose `scraped_at` falls within the last N days. You can still pass an explicit `cnvd_ids` list instead to override the window query.

To regenerate reports from an existing evidence JSON without new web/AI extraction:

```json
"use_existing_evidence_json": true
```

To translate existing evidence JSON in place without building reports:

```bash
.venv/bin/python cnvd_docx.py --config config.json --translate
```

To build reports from existing evidence JSON without rerunning web extraction or sending email:

```bash
.venv/bin/python cnvd_docx.py --config config.json --build-reports
```

`--build-reports` will backfill missing English translations before writing the report files.

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

To upload an existing run folder to eDrive and email the share link:

```bash
.venv/bin/python cnvd_docx.py --config config.json --send-email 20260706_173000
```

This uploads the folder under `output_root` to eDrive and emails the share URL. You can also pass an absolute path or a path already under `output/`.

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
- [`pipeline/email_send.py`](pipeline/email_send.py) — report notification email helper using Zimbra
- [`pipeline/edrive_upload.py`](pipeline/edrive_upload.py) — eDrive upload helper
- [`plugin/zimbra/`](plugin/zimbra/) — reusable Zimbra SOAP client
- [`edrive/`](edrive/) — AnyShare eDrive upload client
