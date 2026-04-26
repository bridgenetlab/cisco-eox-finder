# Workflow: Cisco SWIM Lookup

## Objective

Retrieve Cisco's recommended ("golden") software release for a network device by Product ID, and
optionally evaluate whether a device's running software version is compliant.

---

## Required Inputs

| Input | Required | Notes |
|---|---|---|
| Product ID (PID) | Yes | Single exact PID — no wildcards, no commas, no batching |
| Current Version | No | If provided in a bulk spreadsheet, enables compliance evaluation |

**Important:** The SWIM API does not support wildcard or comma-separated PID queries. One PID per
request. Serial number lookups are not supported.

---

## Credentials

Same as EOX — stored in `.env` in the project root:

```
CISCO_CLIENT_ID=<your-client-id>
CISCO_CLIENT_SECRET=<your-client-secret>
```

The SWIM client imports `get_access_token()` from `cisco_eox.py` and shares the same in-memory
token cache.

---

## Tools

| Tool | Purpose |
|---|---|
| `tools/cisco_swim.py` | SWIM API client + CLI |
| `tools/cisco_eox_webapp.py` | Flask web app — SWIM tab |

---

## Steps

### CLI

```bash
cd tools

# Single PID lookup (human-readable)
python cisco_swim.py --pid ASR-903

# Single PID, raw JSON
python cisco_swim.py --pid WS-C3850-24T --json

# All pages (for PIDs with many suggestions)
python cisco_swim.py --pid ASR-903 --all-pages

# Specific page
python cisco_swim.py --pid ASR-903 --page 2
```

### Web App — Single Search

1. Start the app: `cd tools && python cisco_eox_webapp.py`
2. Open `http://localhost:5001`
3. Click the **SWIM** tab
4. Enter a single PID in the search box and click **Get Suggested Software**
5. Results show all suggestions; the `★ Suggested` badge marks Cisco's recommended release
6. Each suggestion lists its images with name, size, and feature set

### Web App — Bulk Upload

1. Prepare a spreadsheet (`.xlsx` or `.csv`) with at least a Product ID column
   - Optionally include a "Current Version" column for compliance evaluation
2. In the SWIM tab, drag and drop the file or click to browse
3. The app auto-detects:
   - PID column (keywords: "product part", "pid", "part number", "model", etc.)
   - Version column (keywords: "current version", "sw version", "running version", etc.)
4. If detection fails, use the column-mapping dropdowns
5. Click **Process File**
6. Download the enriched Excel file — it will contain three new columns:
   - **SWIM Suggested Release** — Cisco's recommended version string
   - **SWIM Lifecycle** — e.g. `LONG_LIVED`, `CURRENT`
   - **SWIM Compliance** — `Compliant`, `Non-Compliant`, or `Unknown`

---

## Expected Output (per product)

| Field | Description |
|---|---|
| `base_pid` | Product ID as returned by the API |
| `product_name` | Human-readable product name |
| `software_type` | e.g. "IOS XE Software" |
| `mdf_id` | Cisco Metadata Framework ID |
| `suggestions[].is_suggested` | `true` for the recommended ("golden") release |
| `suggestions[].release_format` | Version string, e.g. `16.11.01` |
| `suggestions[].display_name` | Display version, e.g. `16.11.1` |
| `suggestions[].release_date` | ISO date, e.g. `2019-01-31` |
| `suggestions[].lifecycle` | `LONG_LIVED`, `CURRENT`, etc. |
| `suggestions[].train_display` | Release train, e.g. `16.11` |
| `suggestions[].images[].name` | Image filename |
| `suggestions[].images[].size_bytes` | Raw byte count as string |
| `suggestions[].images[].feature_set` | License/feature set label |
| `suggestions[].images[].required_dram` | Minimum RAM, e.g. `2048 MB` |
| `suggestions[].images[].required_flash` | Minimum flash, e.g. `1500 MB` |

---

## SWIM Compliance Rules

| Status | Condition |
|---|---|
| `Compliant` | `current_version` matches `suggested_release` (case-insensitive) |
| `Non-Compliant` | Both values are non-empty and they differ |
| `Unknown` | Either value is missing or empty |

Compliance is only evaluated when a "Current Version" column is present in the bulk spreadsheet.
If that column is absent, `SWIM Compliance` is left blank for all rows.

---

## API Constraints (Critical)

- **One PID per request** — the SWIM API has no batch endpoint
- **Bulk uploads require one API call per unique PID**
  - Example: 500-row spreadsheet with 300 unique PIDs → 300 sequential API calls
  - At roughly 0.5–1 s per call, expect 2–5 minutes for large uploads
- **No wildcard support** — the PID must be an exact match
- **No serial number support** — SWIM only accepts PIDs
- **Not all PIDs are in the catalogue** — valid Cisco hardware PIDs may be absent from the SWIM
  database; these return an empty suggestions list or an `errorDetailsResponse`

---

## Pagination

- `page_index` is 1-based; `last_index` in the response indicates the final page
- Most PIDs return a single page (`last_index == 1`)
- Use `--all-pages` in the CLI to auto-walk all pages
- The web app single search always fetches all pages automatically

---

## Edge Cases

| Situation | Behaviour |
|---|---|
| PID not in SWIM catalogue | `suggestions` list is empty; bulk row left blank |
| `errorDetailsResponse` on a suggestion | `error` field set; displayed inline in UI |
| HTTP 400/404 | `errorDescription` surfaced; no exception propagated |
| HTTP 429 | Exponential backoff (1 s, 2 s, 4 s), up to 3 retries |
| Token expiry | Shared token cache auto-refreshes 60 s before expiry |
| No "Current Version" column | SWIM Compliance column remains blank; other columns still populated |
| Empty version cell in a row | `SWIM Compliance` = `Unknown` for that row |
| Wildcard or comma in PID input | Rejected at `/swim/search` with HTTP 400 error |

---

## Self-Improvement Log

_Append discoveries here — rate limits, unexpected response formats, new edge cases, etc._
