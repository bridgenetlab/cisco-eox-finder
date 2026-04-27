# Agent Instructions

You're working inside the **WAT framework** (Workflows, Agents, Tools). This architecture separates concerns so that probabilistic AI handles reasoning while deterministic code handles execution. That separation is what makes this system reliable.

## The WAT Architecture

**Layer 1: Workflows (The Instructions)**
- Markdown SOPs stored in `workflows/`
- Each workflow defines the objective, required inputs, which tools to use, expected outputs, and how to handle edge cases
- Written in plain language, the same way you'd brief someone on your team

**Layer 2: Agents (The Decision-Maker)**
- This is your role. You're responsible for intelligent coordination.
- Read the relevant workflow, run tools in the correct sequence, handle failures gracefully, and ask clarifying questions when needed
- You connect intent to execution without trying to do everything yourself
- Example: To look up an EOX record, read `workflows/cisco_eox_lookup.md`, confirm credentials are in `.env`, then run `tools/cisco_eox.py --pid <PID>`

**Layer 3: Tools (The Execution)**
- Python scripts in `tools/` that do the actual work
- API calls, data transformations, file I/O
- Credentials and API keys live in `.env` (never hardcoded)
- These scripts are consistent, testable, and fast

**Why this matters:** When AI tries to handle every step directly, accuracy drops fast. If each step is 90% accurate, you're down to 59% success after just five steps. By offloading execution to deterministic scripts, you stay focused on orchestration and decision-making where you excel.

---

## Behavioral Guidelines

These guidelines reduce common AI coding mistakes. They bias toward caution over speed — for trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

## Project Overview

This is the **Cisco EOX Finder** — a tool for querying Cisco's End-of-Life (EOX) and Software Suggestion (SWIM) APIs to surface compliance status for network hardware. It has two interfaces:

1. **CLI** (`tools/cisco_eox.py`, `tools/cisco_swim.py`, `tools/cisco_psirt.py`, `tools/cisco_sn2info.py`) — direct terminal lookups by Product ID or Serial Number
2. **Web App** (`tools/cisco_eox_webapp.py`) — Flask UI with five tabs: Single Search, Bulk Excel Upload, SWIM, PSIRT, and Unified Report

The app is containerized and published to GHCR via GitHub Actions. It can be self-hosted on Docker or Unraid.

---

## Directory Layout

```
cisco-eox-finder/
├── tools/
│   ├── cisco_eox.py          # EOX API client + CLI entry point
│   ├── cisco_swim.py         # SWIM API client + CLI entry point
│   ├── cisco_psirt.py        # PSIRT openVuln API client + CLI entry point
│   ├── cisco_sn2info.py      # SN2INFO contract coverage + PID resolution client + CLI
│   ├── cisco_bug.py          # Bug API v2.0 client + CLI entry point
│   ├── cisco_config_diff.py  # Config diff + risk analyzer (no API credentials needed)
│   ├── cisco_eox_webapp.py   # Flask web app (imports all clients above)
│   └── requirements.txt      # Python dependencies
├── workflows/
│   ├── cisco_eox_lookup.md      # SOP for EOX data retrieval
│   ├── cisco_swim_lookup.md     # SOP for SWIM software suggestion lookup
│   ├── cisco_psirt_lookup.md    # SOP for PSIRT security advisory lookup
│   ├── cisco_sn2info_lookup.md  # SOP for SN2INFO contract coverage + PID resolution
│   ├── cisco_bug_lookup.md      # SOP for Bug API v2.0 lookup
│   └── cisco_config_diff.md     # SOP for Config Diff Risk Analyzer
├── .github/
│   └── workflows/
│       └── docker-publish.yml  # CI/CD: builds and pushes Docker image to GHCR
├── Dockerfile                # Single-stage build; runs cisco_eox_webapp.py
├── docker-compose.yml        # Production deployment config
├── unraid-template.xml       # Unraid NAS container template
├── nginx.conf                # Placeholder (unused; Flask serves directly)
├── .env                      # Secrets — NEVER commit (gitignored)
├── .gitignore
└── CLAUDE.md                 # This file
```

**Temporary files** go in `.tmp/` (gitignored, regenerated as needed). There are no persistent local deliverables — enriched outputs are downloaded by the user directly from the web app.

---

## Tools Reference

### `tools/cisco_eox.py` — Core API Client

The authoritative module for all Cisco EOX V5 API interactions.

**Environment variables required:**
```
CISCO_CLIENT_ID=<your-client-id>
CISCO_CLIENT_SECRET=<your-client-secret>
```

**Key functions:**

| Function | Purpose |
|---|---|
| `get_access_token()` | OAuth2 client credentials flow; in-memory token cache with auto-refresh 60s before expiry |
| `query_by_product_id(pid, page)` | Query by PID; supports wildcards (`*`) and comma-separated list (max 20) |
| `query_by_serial_number(sn, page)` | Query by serial number; comma-separated (max 20) |
| `_parse_eox_record(record)` | Flatten nested API response into a normalized dict |
| `_compliance_status(last_date_str)` | Derive compliance from Last Date of Support |

**Compliance thresholds** (`WARN_DAYS = 180`):

| Status | Condition |
|---|---|
| `noncompliant` | LDoS is in the past |
| `warning` | LDoS within 0–180 days |
| `compliant` | LDoS more than 180 days away |
| `unknown` | Date missing or unparseable |

**Normalized record output:**
```python
{
  "product_id": str,
  "product_name": str,
  "end_of_sale": str,              # YYYY-MM-DD
  "end_of_sw_maintenance": str,
  "end_of_security_support": str,
  "end_of_routine_failure": str,
  "end_of_service_contract": str,
  "last_date_of_support": str,
  "compliance": {
    "status": "compliant" | "warning" | "noncompliant" | "unknown",
    "label": str,
    "days_remaining": int | None
  },
  "migration_product_id": str,
  "migration_info": str,
  "migration_url": str,
  "bulletin_url": str
}
```

**CLI usage:**
```bash
cd tools
python cisco_eox.py --pid WS-C2960X-24TS-L
python cisco_eox.py --sn FHH12345678
python cisco_eox.py --pid "WS-C2960*" --page 2   # wildcard (3+ chars required)
python cisco_eox.py --pid "PID1,PID2" --json      # raw JSON output
```

**API limits to respect:**
- Max 20 PIDs or SNs per request
- Wildcard queries require 3+ characters before `*`
- OAuth token valid ~1 hour; the cache handles refresh automatically
- Token cache is in-memory and per-process (not shared across workers)

---

---

### `tools/cisco_swim.py` — SWIM API Client

Queries the Cisco Software Suggestion API v2 for recommended software releases by Product ID.

**Environment variables required:** same as EOX (`CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET`).
`get_access_token()` is imported from `cisco_eox` — the token cache is shared.

**Key functions:**

| Function | Purpose |
|---|---|
| `query_swim_by_pid(pid, page_index)` | Single-page SWIM query; returns `{query, pagination, products, error}` |
| `query_all_pages_swim_by_pid(pid)` | Walks all pages; returns combined products list |
| `get_suggested_release(pid)` | Returns `{suggested_release, lifecycle}` for the first `isSuggested=True` entry, or `None` |
| `_parse_swim_product(product)` | Flatten API product dict → normalized dict |
| `_parse_swim_suggestion(suggestion)` | Flatten API suggestion dict |
| `_parse_swim_image(image)` | Flatten API image dict |
| `_swim_compliance(current_version, suggested_release)` | Returns `Compliant` / `Non-Compliant` / `Unknown` |

**Normalized product output:**
```python
{
  "base_pid":      str,
  "mdf_id":        str,
  "product_name":  str,
  "software_type": str,
  "suggestions": [
    {
      "is_suggested":   bool,
      "release_format": str,   # e.g. "16.11.01"
      "release_date":   str,   # YYYY-MM-DD
      "lifecycle":      str,   # e.g. "LONG_LIVED"
      "display_name":   str,
      "train_display":  str,
      "images": [
        {"name": str, "size_bytes": str, "feature_set": str,
         "description": str, "required_dram": str, "required_flash": str}
      ],
      "error": str | None
    }
  ]
}
```

**CLI usage:**
```bash
cd tools
python cisco_swim.py --pid ASR-903
python cisco_swim.py --pid WS-C3850-24T --json
python cisco_swim.py --pid ASR-903 --all-pages
```

**API constraints:**
- One PID per request — no wildcards, no comma-separated lists, no SN lookup
- Not all Cisco PIDs are in the SWIM catalogue; missing PIDs return an empty suggestions list

---

### `tools/cisco_psirt.py` — PSIRT openVuln API Client

Queries the Cisco PSIRT openVuln API v2 for security advisories by OS type and software version.

**Environment variables required:** same as EOX (`CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET`).
`get_access_token()` is imported from `cisco_eox` — the token cache is shared.

Optional: `PSIRT_SEVERITY_THRESHOLD` (default `Critical`; set to `High` to flag High advisories too).

**Supported OS types:** `ios`, `iosxe`, `nxos`, `asa`, `ftd`, `fxos`, `fmc`

**Key functions:**

| Function | Purpose |
|---|---|
| `query_psirt_by_version(os_type, version)` | Returns `{os_type, version, advisories, compliance, error}` |
| `get_psirt_summary(os_type, version)` | Returns `{compliance, critical_count, advisory_ids, cves}` or `None` |
| `_parse_psirt_advisory(adv)` | Flatten API advisory dict → normalized dict |
| `_psirt_compliance(advisories)` | Returns `Compliant` / `Non-Compliant` based on SEVERITY_THRESHOLD |

**Compliance rules:**

| Status | Condition |
|---|---|
| `Non-Compliant` | Advisory with SIR ≥ `SEVERITY_THRESHOLD` found |
| `Compliant` | No advisory meets the threshold (including empty advisory list) |
| `NA` | No version provided — callers set this when version is absent |

**Normalized advisory output:**
```python
{
    "advisory_id":     str,   # e.g. "cisco-sa-..."
    "title":           str,
    "sir":             str,   # Critical / High / Medium / Low
    "cvss_score":      str,
    "cves":            list[str],
    "bug_ids":         list[str],
    "first_published": str,   # ISO datetime
    "publication_url": str,
}
```

**CLI usage:**
```bash
cd tools
python cisco_psirt.py --os-type iosxe --version 16.11.1
python cisco_psirt.py --os-type iosxe --version 16.11.1 --json
python cisco_psirt.py --os-type iosxe --version 16.11.1 --severity Critical
```

**API constraints:**
- One call per (os_type, version) pair — no batch endpoint
- Rate limits: 5 calls/sec · 30 calls/min · 5,000 calls/day
- No PID or serial number lookup — OS type + version required
- Empty advisory list → Compliant (version not in catalogue is not an error)

---

### `tools/cisco_bug.py` — Bug API v2.0 Client

Queries the Cisco Bug API v2.0 for known defects (CSCxxx IDs) by Product ID and optional software version.

**Environment variables required:** same as EOX (`CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET`).
`get_access_token()` is imported from `cisco_eox` — the token cache is shared.

Optional: `BUG_SEVERITY_THRESHOLD` (default `2`; numeric 1=Critical, 2=High, 3=Moderate, 4=Minor).

**Key functions:**

| Function | Purpose |
|---|---|
| `get_bugs_by_pid(pid)` | Returns all normalized bugs for a PID (all pages) |
| `get_bugs_by_pid_version(pid, version)` | Bugs affecting a specific PID + version; falls back to `get_bugs_by_pid` on 404 |
| `get_bug_summary(pid, version="")` | Convenience: returns `{bug_compliance, open_count, critical_count, bug_ids}` or `None` |
| `_bug_compliance(bugs)` | Returns `"Compliant"` / `"Non-Compliant"` based on open bugs at threshold severity |
| `_parse_bug(bug)` | Flatten API bug dict → normalized dict |

**Compliance rules:**

| Status | Condition |
|---|---|
| `Non-Compliant` | Open bug with `severity <= BUG_SEVERITY_THRESHOLD` found |
| `Compliant` | No open bugs meet the threshold (including empty list or all Fixed) |
| `NA` | No PID provided — callers set this when PID is absent |

**Normalized bug output:**
```python
{
    "bug_id":                  str,   # e.g. "CSCtr13789"
    "headline":                str,
    "severity":                int,   # 1=Critical, 2=High, 3=Moderate, 4=Minor
    "severity_label":          str,
    "status":                  str,   # O=Open, F=Fixed, T=Terminated, E=Unreproducible, D=Duplicate
    "status_label":            str,
    "product":                 str,
    "base_pid":                str,
    "known_affected_releases": str,
    "known_fixed_releases":    str,
    "created_date":            str,   # YYYY-MM-DD
    "last_modified_date":      str,
    "support_case_count":      str,
}
```

**CLI usage:**
```bash
cd tools
python cisco_bug.py --pid WS-C3560-48PS-S
python cisco_bug.py --pid WS-C3560-48PS-S --version "12.2(25)SEE2"
python cisco_bug.py --pid WS-C3560-48PS-S --json
python cisco_bug.py --batch-file devices.txt   # one pid or pid:version per line
```

**API constraints:**
- One PID per request — no batch endpoint
- Pagination: 10 bugs per page; client walks all pages automatically
- Stop condition: `len(page_bugs) < 10` (last page)
- 400/404 treated as no bugs (empty result → `Compliant`)

---

### `tools/cisco_sn2info.py` — SN2INFO API Client

Queries the Cisco SN2INFO v2 API to resolve serial numbers to Product IDs and retrieve contract coverage status.

**Environment variables required:** same as EOX (`CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET`).
`get_access_token()` is imported from `cisco_eox` — the token cache is shared.

**Key functions:**

| Function | Purpose |
|---|---|
| `get_coverage_summary(sns)` | Batch GET `/coverage/summary/serial_numbers/{SNs}`; returns `{SN_UPPER: coverage_dict}` |
| `get_pids_from_sns(sns)` | Convenience: resolve SNs to orderable PIDs; returns `{SN_UPPER: pid}` |

**Normalized coverage output:**
```python
{
    "coverage_status":   str,   # "Active" or "Inactive"
    "coverage_end_date": str,   # YYYY-MM-DD
    "contract_number":   str,
    "service_level":     str,   # e.g. "SMARTNET 8X5XNBD"
    "base_pid":          str,
    "orderable_pid":     str,   # preferred for SWIM lookup
}
```

**CLI usage:**
```bash
cd tools
python cisco_sn2info.py --sn FOC10220LK9
python cisco_sn2info.py --sn "SN1,SN2,SN3" --json
```

**API constraints:**
- Endpoint: `GET /sn2info/v2/coverage/summary/serial_numbers/{SN1,SN2,...}`
- Batch up to 20 SNs per call (conservative URL length limit)
- Returns both PID resolution and coverage status in a single call
- Rate limits: 5 calls/sec · 30 calls/min · 5,000 calls/day

---

### `tools/cisco_eox_webapp.py` — Flask Web Application

Imports `cisco_eox`, `cisco_swim`, `cisco_psirt`, `cisco_sn2info`, and `cisco_bug`. Serves a single-page application with seven tabs.

**Routes:**

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Serve embedded HTML/CSS/JS UI |
| `/health` | GET | Health check; returns `{"status": "ok"}` |
| `/search` | POST | Single PID/SN EOX lookup; returns `{results: [...]}` |
| `/upload` | POST | Accept `.xlsx`/`.csv`, enrich with EOX data, store as job |
| `/download/<job_id>` | GET | Stream EOX-enriched Excel for download |
| `/swim/search` | POST | Single PID SWIM lookup; returns `{result: {...}}` |
| `/swim/upload` | POST | Accept `.xlsx`/`.csv`, enrich with SWIM suggested release + compliance |
| `/swim/download/<job_id>` | GET | Stream SWIM-enriched Excel for download |
| `/psirt/search` | POST | Single version PSIRT lookup; returns `{result: {...}}` |
| `/psirt/upload` | POST | Accept `.xlsx`/`.csv`, enrich with PSIRT advisory + compliance data |
| `/psirt/download/<job_id>` | GET | Stream PSIRT-enriched Excel for download |
| `/bug/search` | POST | Single PID bug lookup; returns `{result: {...}}` |
| `/bug/upload` | POST | Accept `.xlsx`/`.csv`, enrich with Bug compliance data |
| `/bug/download/<job_id>` | GET | Stream Bug-enriched Excel for download |
| `/bug/html/<job_id>` | GET | HTML report for a Bug job |
| `/config-diff/analyze` | POST | Accept two config text blocks, return risk-annotated diff |
| `/config-diff/bulk` | POST | Accept `.zip` of config files + optional `baseline` field; diff each file vs baseline |
| `/config-diff/bulk-download/<job_id>` | GET | Stream bulk diff Excel summary for download |
| `/unified/upload` | POST | Accept `.xlsx`/`.csv`, enrich with EOX + Coverage + SWIM + PSIRT + Bug data |
| `/unified/download/<job_id>` | GET | Stream unified report Excel for download |

**EOX bulk upload behavior:**
1. Reads file (`.xlsx`/`.xls`/`.csv`) into a Pandas DataFrame (all columns as strings)
2. Auto-detects PID column (keywords: "product part", "pid", "part number", "part_no", "model", "pn")
3. Auto-detects SN column (keywords: "serial number", "s/n", "serial_no", "serial")
4. Batches unique PIDs in groups of 20 to respect API limits
5. Appends 7 new columns: End of Sale, End of SW, End of Security, End of Service Contract, Last Date, Compliance, Migration PID
6. Stores enriched DataFrame in SQLite job store (UUID key, 24h TTL)
7. Returns job ID and preview data; download triggered separately

**SWIM bulk upload behavior:**
1. Reads file (`.xlsx`/`.xls`/`.csv`) into a Pandas DataFrame (all columns as strings)
2. Auto-detects PID column using same keywords as EOX
3. Auto-detects version column (keywords: "current version", "sw version", "running version", "ios version", "firmware")
4. **One API call per unique PID** — SWIM has no batch endpoint; large uploads can be slow
5. Appends 3 new columns: SWIM Suggested Release, SWIM Lifecycle, SWIM Compliance
6. SWIM Compliance is only populated when a version column is detected
7. Stores enriched DataFrame in the shared SQLite job store

**PSIRT bulk upload behavior:**
1. Reads file (`.xlsx`/`.xls`/`.csv`) into a Pandas DataFrame (all columns as strings)
2. Auto-detects version column (same keywords as SWIM)
3. Auto-detects OS Type column (keywords: "os type", "software type", "platform")
4. If no OS Type column, all rows use `default_os_type` (default: `iosxe`; selectable in mapping UI)
5. **One API call per unique (os_type, version) pair** — rate limit: 5 calls/sec
6. Appends 4 new columns: PSIRT Compliance, PSIRT Critical Advisories, PSIRT Advisory IDs, PSIRT CVEs
7. Rows with no version value get `PSIRT Compliance = NA`
8. Stores enriched DataFrame in the shared SQLite job store

**Bug bulk upload behavior:**
1. Reads file (`.xlsx`/`.xls`/`.csv`) into a Pandas DataFrame (all columns as strings)
2. Auto-detects PID column (same keywords as EOX)
3. Auto-detects optional version column (same keywords as SWIM)
4. If no PID column found: returns `needs_mapping` (context: `"bug"`) for manual mapping
5. **One API call per unique (pid, version) pair** — no batch endpoint
6. Appends 4 new columns: Bug Compliance, Bug Open Count, Bug IDs, Bug Fixed Count
7. Rows with no PID get `Bug Compliance = NA`
8. Stores enriched DataFrame in the shared SQLite job store

**Unified Report bulk upload behavior:**
1. Reads file (`.xlsx`/`.xls`/`.csv`) into a Pandas DataFrame (all columns as strings)
2. Auto-detects PID column, SN column, version column, and OS Type column
3. **Requires at least a PID or SN column** — returns `needs_mapping` (context: `"unified"`) if neither found
4. Runs all five lookups in sequence: EOX → Coverage (SN2INFO) → SWIM → PSIRT → Bug
5. For SWIM/Bug when no PID column: uses `orderable_pid` resolved from SN2INFO coverage lookup
6. Appends 24 new columns total: 7 EOX + 4 Coverage + 3 SWIM + 4 PSIRT + 4 Bug + 2 Urgency
7. Coverage columns populated only when SN column is present
8. Rows without a version value get `PSIRT Compliance = NA`
9. Rows without a resolvable PID get `Bug Compliance = NA`
10. Computes Urgency Score (0–100) and Urgency Level (Critical/High/Medium/Low) from all compliance signals
11. Stores enriched DataFrame in the shared SQLite job store

**Starting the web app:**
```bash
cd tools
python cisco_eox_webapp.py    # runs on http://localhost:5001
```

**Limits:** `MAX_CONTENT_LENGTH = 50 MB`

**Optional alert env vars:**

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_URL` | — | Slack/Teams incoming webhook URL for non-compliant alerts |
| `SMTP_HOST` | — | SMTP server hostname (required to enable email alerts) |
| `SMTP_PORT` | `587` | SMTP port (587 = STARTTLS, 465 = SSL) |
| `SMTP_USER` | — | SMTP login username |
| `SMTP_PASS` | — | SMTP login password |
| `ALERT_EMAIL_FROM` | `SMTP_USER` | Sender address |
| `ALERT_EMAIL_TO` | — | Recipient(s), comma-separated (required to enable email alerts) |
| `ALERT_MIN_NONCOMPLIANT` | `1` | Minimum non-compliant devices to trigger an email |

Email alerts fire automatically after every bulk job (EOX / SWIM / PSIRT / Bug / Unified) when the non-compliant count meets the threshold. The Dashboard tab shows the current SMTP config and has a **✉ Send Test Email** button.

---

## Workflows Reference

### `workflows/cisco_eox_lookup.md`

The SOP for any EOX data retrieval task. Always read this before querying. Key sections:
- Required inputs and credential setup
- CLI vs. web app usage paths
- Expected output field descriptions
- Compliance rule definitions
- Pagination instructions for wildcard queries
- Edge cases: invalid PIDs, missing records, token expiry, rate limits
- Self-improvement log (append discoveries here)

### `workflows/cisco_sn2info_lookup.md`

The SOP for serial number → PID resolution and contract coverage lookups. Key sections:
- Coverage status definitions (Active / Inactive)
- CLI usage
- Web App usage via the Unified Report tab
- Expected output fields (coverage_status, orderable_pid, etc.)
- API constraints (batch size 20, pagination, rate limits)

### `workflows/cisco_bug_lookup.md`

The SOP for Bug API v2.0 lookups. Key sections:
- Compliance rules (Open bugs only; numeric severity threshold)
- CLI usage (single PID, PID+version, batch file)
- Web App: Bugs tab single search + bulk upload + Unified Report integration
- Expected output fields (Bug Compliance, Bug Open Count, Bug IDs)
- API constraints (10/page pagination, 400/404 → Compliant, version fallback)
- Edge cases (Fixed bugs ignored, NA when no PID)

---

## Dependencies

All dependencies are in `tools/requirements.txt`:

```
requests>=2.31.0      # HTTP + OAuth2
flask>=3.0.0          # Web framework
python-dotenv>=1.0.0  # Load .env
pandas>=2.0.0         # Excel processing
openpyxl>=3.1.0       # Excel writer engine
```

Install:
```bash
pip install -r tools/requirements.txt
```

---

## Deployment

### Local Docker

```bash
# With docker-compose (recommended)
CISCO_CLIENT_ID=xxx CISCO_CLIENT_SECRET=yyy docker compose up

# Or pass via .env file in the project root
docker compose up
```

The container exposes port **5001** and has a built-in health check (HTTP GET `/` every 30s).

### CI/CD

`.github/workflows/docker-publish.yml` triggers on:
- Push to `main` or `master` → publishes `latest` tag
- Version tags (`v*.*.*`) → publishes semver tags

Image published to: `ghcr.io/bridgenetlab/cisco-eox-finder`

### Unraid

Use `unraid-template.xml` via the Unraid Community Applications template system. Requires `CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET` to be set in the container settings.

---

## Development Conventions

**Code style:**
- Python 3.11+ type hints in function signatures
- Docstrings on all public functions
- No inline comments unless the behavior is non-obvious

**Error handling:**
- Validate credentials at startup (raise `ValueError` if missing)
- Gracefully handle missing/malformed date fields (`unknown` status)
- Do not swallow exceptions silently — let callers see failures

**Adding a new query type:**
1. Add a new function in `cisco_eox.py` following the `query_by_*` pattern
2. Add a corresponding route in `cisco_eox_webapp.py` if a UI is needed
3. Update `workflows/cisco_eox_lookup.md` with the new capability

**No tests directory exists.** Before running any script that makes live API calls, confirm credentials are in `.env` and check with the user if it will consume billable API quota.

**Secrets rule:** `.env` is gitignored. Never put credentials in code, Docker images, or workflow files. Use environment variables passed at runtime.

---

## How to Operate

**1. Look for existing tools first**
Before building anything, check `tools/` and the relevant workflow. Only create new scripts when nothing covers the task.

**2. Plan before you act**
For multi-step tasks, write out a brief plan with a verifiable check for each step before touching any code. Confirm the plan if the scope is ambiguous.

**3. Learn and adapt when things fail**
- Read the full error trace
- Fix the script and retest (confirm with the user before re-running paid API calls)
- Document findings in the workflow's Self-Improvement Log

**4. Keep workflows current**
Update `workflows/cisco_eox_lookup.md` when you discover rate limits, new edge cases, or better approaches. Don't create or overwrite workflows without asking.

---

## The Self-Improvement Loop

1. Identify what broke
2. Fix the tool
3. Verify the fix works
4. Update the workflow
5. Move on with a stronger system

---

## Bottom Line

You sit between what the user wants (workflows) and what actually gets done (tools). Read instructions, make smart decisions, call the right scripts, recover from errors, and keep improving the system as you go.

Stay pragmatic. Stay reliable. Keep learning.
