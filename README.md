# Vulnerability Evidence-Card Report Pipeline

Generate a weekly vulnerability report from the unified MongoDB `vulnerabilities.news` collection. The pipeline produces:

- Chinese and English DOCX reports
- A Chinese weekly XLSX disclosure workbook
- A reusable evidence cache in `cnvd_evidence_cards.json`

All commands use the repository's [config.json](config.json). There is no `--config` option.

## Quick start

1. Install dependencies and create your local environment file.

   ```bash
   pip install -r requirements.txt
   cp .env.example .env
   ```

2. Edit [config.json](config.json) and `.env`.

3. Run the full pipeline.

   ```bash
   .venv/bin/python main.py
   ```

The full pipeline selects vulnerabilities, searches for evidence, builds both DOCX files and the XLSX workbook, then emails the dated output folder as a ZIP to the configured Zimbra transfer mailbox by default.

To email the folder directly to the recipients in `config.json` as a ZIP attachment, run:

```bash
.venv/bin/python main.py --email-delivery attachment
```

For an existing report folder:

```bash
.venv/bin/python main.py --send-email 20260706_173000 --email-delivery attachment
```

Attachment delivery preserves the folder structure and skips eDrive and the CloudAMQP transfer bridge. It requires only the Zimbra credentials and configured email recipients for delivery. Set `"email_delivery": "attachment"` in `config.json` to make it the default; `--email-delivery edrive` selects the original eDrive workflow for a run. Generated folders remain available locally after direct sending. Normal email attachment size limits apply.

## How it works

1. Optionally match recent records from every scraper provider to the software-cluster summary.
2. Load the selected records from MongoDB.
3. Search SearXNG or Firecrawl for each vulnerability.
4. Extract source-grounded evidence in Chinese with the configured AI server.
5. Translate the merged report text to English.
6. Write the evidence cache and dated DOCX/XLSX output files.
7. Deliver the run folder: send directly to recipients as a ZIP in attachment mode, or use the Zimbra transfer bridge and publish a CloudAMQP wake-up in eDrive mode.

The receiver runs `--receive-transfer`, listens on CloudAMQP, downloads the transfer ZIP from Zimbra, uploads it to eDrive, and sends the share link to the report recipient. With `--email-delivery attachment`, the receiver emails the folder ZIP to recipients instead. After successful delivery, it deletes the received local folder and the transfer email.

## Commands

Run these from the repository root.

| Command | What it does |
| --- | --- |
| `.venv/bin/python main.py` | Run the complete report pipeline and send the output ZIP to Zimbra. |
| `.venv/bin/python main.py --email-delivery attachment` | Run the complete report pipeline and email the output folder ZIP directly to the configured To, CC, and BCC recipients. |
| `.venv/bin/python main.py --local-only` | Run the complete report pipeline and save the dated output folder locally without sending email or publishing a CloudAMQP wake-up. |
| `.venv/bin/python main.py --cluster-match` | Match vulnerabilities to software clusters only; does not search or write reports. |
| `.venv/bin/python main.py --translate` | Add or refresh English translations in the existing evidence JSON. |
| `.venv/bin/python main.py --build-reports` | Build reports from existing evidence JSON; does not search or send email. Optionally uploads to eDrive when configured and using eDrive delivery. |
| `.venv/bin/python main.py --send-transfer 20260706_173000` | Send an existing output folder as a ZIP through Zimbra and publish a CloudAMQP wake-up. |
| `.venv/bin/python main.py --send-transfer --fake` | Create a tiny synthetic test folder, ZIP it, send through Zimbra, and publish a CloudAMQP wake-up. |
| `.venv/bin/python main.py --receive-transfer` | Listen on CloudAMQP, then process each transfer ZIP from Zimbra (eDrive upload + share-link email), and delete the local output folder after upload. |
| `.venv/bin/python main.py --receive-transfer --email-delivery attachment` | Listen on CloudAMQP, then email each received folder ZIP to recipients and delete the received local folder after successful delivery. |
| `.venv/bin/python main.py --receive-transfer --fake` | Skip final delivery; check eDrive connectivity only in eDrive mode. Still extracts ZIP and deletes the transfer mail, and retains the received local folder. |
| `.venv/bin/python main.py --send-email 20260706_173000` | Upload an existing output folder to eDrive and email its share link. |
| `.venv/bin/python main.py --send-email 20260706_173000 --email-delivery attachment` | Email an existing report folder as a ZIP attachment to the configured recipients, without eDrive. |
| `.venv/bin/python main.py --self-test` | Run the local test suite without MongoDB, search, AI, eDrive, or Zimbra. |
| `.venv/bin/python -m unittest discover -s tests -v` | Run the test suite directly. |

For `--send-transfer` and `--send-email`, pass either a run-folder name under `output/` or an absolute folder path.

## Configuration

### config.json

[config.json](config.json) is always loaded from the repository root.

| Setting | Purpose |
| --- | --- |
| `scrape_days` | Number of recently observed CNVD records to load from `vulnerabilities.news` when `cnvd_ids` is not set. |
| `mongo_uri` | MongoDB connection URI for the `vulnerabilities` database. Set `MONGODB_URI` in `.env` to override it, especially when using credentials. |
| `cnvd_ids` | Optional CNVD ID list; resolves `cnvd:<id>` records from `vulnerabilities.news` and overrides `scrape_days`. |
| `use_filtered_vuln_ids` | Enable software-cluster matching against all providers in `vulnerabilities.news`, identified by `source.provider`. |
| `software_cluster_csv` | Sorted software-cluster summary used for matching. |
| `vuln_match_top_n` | Maximum accepted matches per run (default `20`; this configuration uses `30`). |
| `vuln_match_max_rejected` | Maximum AI-rejected candidates per run. `0` means unlimited (default); this configuration uses `100`. |
| `vuln_match_max_per_cluster` | Maximum accepted matches per software cluster. `0` means unlimited. |
| `vuln_match_enable_thinking` | Enable thinking for AI software-cluster confirmation (`true` by default). Set to `false` to disable it. |
| `vuln_match_thinking_budget_tokens` | Thinking-token budget for software-cluster confirmation; ignored when thinking is disabled. |
| `report_identity_batch_size` | Number of unique vendor/product summaries sent to AI together (default `8`). Unchanged summaries are cached. |
| `search_provider` | `firecrawl` or `searxng`. |
| `firecrawl_retries` | Max Firecrawl attempts on failure (default `5`). |
| `firecrawl_retry_wait` | Seconds to wait between Firecrawl retries (default `30`). |
| `ai_base_url`, `ai_model` | Local OpenAI-compatible AI server used for extraction and translation. |
| `use_existing_evidence_json` | Reuse cached evidence and fetch only missing cards. |
| `output_root` | Parent directory for timestamped report folders. |
| `email_receiver` | To recipients for report emails. Accepts a JSON array or comma-separated string. Overrides `EMAIL_RECEIVER` in `.env`, including when explicitly empty. |
| `email_cc` | CC recipients for report emails. Accepts a JSON array or comma-separated string; defaults to empty. |
| `email_bcc` | BCC recipients for report emails. Accepts a JSON array or comma-separated string; defaults to empty. |
| `email_delivery` | `edrive` (default) or `attachment`. Applies to the full pipeline, `--send-email`, and `--receive-transfer`; override with `--email-delivery`. Attachment mode also skips the optional eDrive upload for `--build-reports`. |
| `email_title` | Subject suffix for report emails in either delivery mode. |
| `email_body` | Body for the eDrive share-link notification. |
| `email_attachment_body` | Optional body for ZIP attachment emails. Defaults to `本週漏洞報告文件已附於郵件附件，敬請查閱。`. |

Configure report recipients in `config.json`, for example:

```json
{
  "email_receiver": ["recipient@example.com"],
  "email_cc": ["copy@example.com"],
  "email_bcc": ["private@example.com"]
}
```

Use `[]` for any unused recipient field. At least one address across To, CC, and BCC is required. These settings apply to attachment and eDrive report emails, including `--receive-transfer`. Transfer-bridge emails still go to `ZIMBRA_EMAIL`. `EMAIL_RECEIVER` in `.env` is used only when `email_receiver` is absent from `config.json`; an explicit empty value prevents that fallback. Keep the sender credentials in `.env`.

Use JSON booleans (`true` or `false`, without quotes) for `vuln_match_enable_thinking`. Evidence extraction and English translation keep thinking disabled.

AI confirmation checks candidates from highest score to lowest and stops when either the accepted or rejected limit is reached, or candidates run out. Candidates skipped because a cluster is full do not count as AI rejections. Set `vuln_match_max_rejected` to a non-negative integer. The pipeline continues with the accepted records collected so far, which may be fewer than `vuln_match_top_n`; if none were accepted, it exits without building reports.

Output filenames come from `output_docx` and `output_weekly_excel`. With `output_date_prefix: true` (the default), the pipeline prefixes each file with the report date range.

The pipeline always creates Chinese and English DOCX reports. Word reports use `docx_template` and keep the original nine-row vulnerability tables, merged cells, field order and page settings. Readability improvements stay within that layout: consistent fonts, spacing, cell padding, subtle shading and clickable source links. Full affected versions appear in the existing scope row. The XLSX workbook keeps the regional review blocks and leaves `是否涉及` blank for human review, with a dropdown, frozen headings and readable row shading.

Before building reports, AI summarizes one vendor and one canonical product name from the supplied title, product/vendor fields and matched software. Product labels omit versions, builds and edition lists; digits belonging to actual brands such as Microsoft 365 remain. Labels are cached under `report_identity` and refreshed when their inputs or model change. Invalid or unavailable AI responses fall back to concise source labels. The original product/vendor lists and affected versions remain in the evidence cache; Word still shows affected versions separately.

Both report formats retain the complete CVE list. Missing source fields are shown as `-`. Mongo `_id` remains the record identity in shortlists and evidence caches. The legacy `cnvd_id` field retains the readable advisory identifier for compatibility.

Filtering has no fixed provider list. Shared mapping handles CNVD/CNNVD, AVD, CVE/NVD, GitHub advisories, HKCERT/GovCERT, HPE, Huawei, MSRC, Qianxin, and Zimbra payloads; other providers use common product, vendor, description, remediation, and reference fields. Nested affected packages and vulnerable CPEs are normalized for matching. Keyword candidates still require AI confirmation, and configured severity and date filters apply to every provider. Records without a severity do not pass a configured severity filter.

### .env

Copy [`.env.example`](.env.example) to `.env`, then supply the credentials needed by the commands you use.

| Variable | Required for |
| --- | --- |
| `FIRECRAWL_API_KEY` | Firecrawl searches, including SearXNG fallback. Comma-separated keys rotate on failure. |
| `ZIMBRA_HOST`, `ZIMBRA_EMAIL`, `ZIMBRA_PASSWORD` | Sending or receiving transfer emails and email notifications. |
| `CLOUDAMQP_URL`, `CLOUDAMQP_QUEUE` | Transfer wake-up listener (`--receive-transfer`) and publish after `--send-transfer` / full pipeline in eDrive mode. Not needed for direct attachment delivery. |
| `EMAIL_RECEIVER` | Optional legacy To-recipient fallback when `email_receiver` is absent from `config.json`. Comma-separated for multiple recipients. |
| `EDRIVE_USERNAME`, `EDRIVE_PASSWORD`, `EDRIVE_REMOTE_PATH`, `EDRIVE_BASE_URL` | Uploading to eDrive. |

## Services and dependencies

- Python packages from [requirements.txt](requirements.txt)
- A reachable MongoDB server at `mongo_uri` in `config.json` (or `MONGODB_URI` in `.env`)
- `curl` and `openssl` in `PATH` for eDrive login and uploads
- An OpenAI-compatible local AI server (the configured server must support `chat_template_kwargs`)
- SearXNG when `search_provider` is `searxng`, or a Firecrawl API key when using Firecrawl
- PyPI [`zimbra-client`](https://pypi.org/project/zimbra-client/) and [`edrive-anyshare`](https://pypi.org/project/edrive-anyshare/1.0.0/) packages
## Project layout

- [main.py](main.py) — CLI entry point
- [pipeline/cli.py](pipeline/cli.py) — command orchestration
- [pipeline/vuln_match.py](pipeline/vuln_match.py) — software-cluster matching
- [pipeline/news_schema.py](pipeline/news_schema.py) — shared scraper field mapping
- [pipeline/search.py](pipeline/search.py) — SearXNG and Firecrawl search
- [pipeline/evidence.py](pipeline/evidence.py) — evidence extraction, translation, and cache handling
- [pipeline/docx_report.py](pipeline/docx_report.py) — DOCX report generation
- [pipeline/excel_report.py](pipeline/excel_report.py) — XLSX workbook generation
- [cluster/software_cluster_summary_v3.csv](cluster/software_cluster_summary_v3.csv) — software clusters used for matching
- [tests/](tests/) — local test suite
