# CNVD Evidence-Card Report Pipeline

Generate a weekly vulnerability report from CNVD/CNNVD data. The pipeline produces:

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

The full pipeline selects vulnerabilities, searches for evidence, builds both DOCX files and the XLSX workbook, then emails the dated output folder as a ZIP to the configured Zimbra transfer mailbox.

## How it works

1. Optionally match recent CNVD/CNNVD records to the software-cluster summary.
2. Load the selected records from MongoDB.
3. Search SearXNG or Firecrawl for each vulnerability.
4. Extract source-grounded evidence in Chinese with the configured AI server.
5. Translate the merged report text to English.
6. Write the evidence cache and dated DOCX/XLSX output files.
7. Send the run folder through the Zimbra transfer bridge.

The eDrive receiver downloads the transfer ZIP, uploads it to eDrive, and sends the share link to the report recipient.

## Commands

Run these from the repository root.

| Command | What it does |
| --- | --- |
| `.venv/bin/python main.py` | Run the complete report pipeline and send the output ZIP to Zimbra. |
| `.venv/bin/python main.py --cluster-match` | Match vulnerabilities to software clusters only; does not search or write reports. |
| `.venv/bin/python main.py --translate` | Add or refresh English translations in the existing evidence JSON. |
| `.venv/bin/python main.py --build-reports` | Build reports from existing evidence JSON; does not search or send transfer email. |
| `.venv/bin/python main.py --send-transfer 20260706_173000` | Send an existing output folder as a ZIP through Zimbra. |
| `.venv/bin/python main.py --receive-transfer` | Receive the latest transfer ZIP, upload it to eDrive, and email the share link. |
| `.venv/bin/python main.py --send-email 20260706_173000` | Upload an existing output folder to eDrive and email its share link. |
| `.venv/bin/python main.py --self-test` | Run the local test suite without MongoDB, search, AI, eDrive, or Zimbra. |
| `.venv/bin/python -m unittest discover -s tests -v` | Run the test suite directly. |

For `--send-transfer` and `--send-email`, pass either a run-folder name under `output/` or an absolute folder path.

## Configuration

### config.json

[config.json](config.json) is always loaded from the repository root.

| Setting | Purpose |
| --- | --- |
| `scrape_days` | Number of recently scraped CNVD records to load when `cnvd_ids` is not set. |
| `cnvd_ids` | Optional explicit list of IDs; overrides `scrape_days`. |
| `use_filtered_vuln_ids` | Enable software-cluster matching before search. |
| `software_cluster_csv` | Sorted software-cluster summary used for matching. |
| `search_provider` | `firecrawl` or `searxng`. |
| `ai_base_url`, `ai_model` | Local OpenAI-compatible AI server used for extraction and translation. |
| `use_existing_evidence_json` | Reuse cached evidence and fetch only missing cards. |
| `output_root` | Parent directory for timestamped report folders. |
| `email_title`, `email_body` | Subject suffix and body for the final eDrive share-link notification. |

Output filenames come from `output_docx` and `output_weekly_excel`. With `output_date_prefix: true` (the default), the pipeline prefixes each file with the report date range.

The pipeline always creates Chinese and English DOCX reports. The XLSX workbook is Chinese and leaves `是否涉及` blank for human review.

### .env

Copy [`.env.example`](.env.example) to `.env`, then supply the credentials needed by the commands you use.

| Variable | Required for |
| --- | --- |
| `FIRECRAWL_API_KEY` | Firecrawl searches, including SearXNG fallback. |
| `ZIMBRA_HOST`, `ZIMBRA_EMAIL`, `ZIMBRA_PASSWORD` | Sending or receiving transfer emails and email notifications. |
| `EMAIL_RECEIVER` | Sending the final eDrive share-link notification. |
| `EDRIVE_USERNAME`, `EDRIVE_PASSWORD`, `EDRIVE_REMOTE_PATH`, `EDRIVE_BASE_URL` | Uploading to eDrive. |

## Services and dependencies

- Python packages from [requirements.txt](requirements.txt)
- `mongosh` in `PATH`
- An OpenAI-compatible local AI server (the configured server must support `chat_template_kwargs`)
- SearXNG when `search_provider` is `searxng`, or a Firecrawl API key when using Firecrawl
- The local [eDrive client](plugin/edrive/) and [Zimbra client](plugin/zimbra/)

## Project layout

- [main.py](main.py) — CLI entry point
- [pipeline/cli.py](pipeline/cli.py) — command orchestration
- [pipeline/vuln_match.py](pipeline/vuln_match.py) — software-cluster matching
- [pipeline/search.py](pipeline/search.py) — SearXNG and Firecrawl search
- [pipeline/evidence.py](pipeline/evidence.py) — evidence extraction, translation, and cache handling
- [pipeline/docx_report.py](pipeline/docx_report.py) — DOCX report generation
- [pipeline/excel_report.py](pipeline/excel_report.py) — XLSX workbook generation
- [cluster/software_cluster_summary_v3.csv](cluster/software_cluster_summary_v3.csv) — software clusters used for matching
- [tests/](tests/) — local test suite
