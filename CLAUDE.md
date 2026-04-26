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

1. **CLI** (`tools/cisco_eox.py`, `tools/cisco_swim.py`) — direct terminal lookups by Product ID or Serial Number
2. **Web App** (`tools/cisco_eox_webapp.py`) — Flask UI with three tabs: Single Search, Bulk Excel Upload, and SWIM

The app is containerized and published to GHCR via GitHub Actions. It can be self-hosted on Docker or Unraid.

---

## Directory Layout

```
cisco-eox-finder/
├── tools/
│   ├── cisco_eox.py          # EOX API client + CLI entry point
│   ├── cisco_swim.py         # SWIM API client + CLI entry point
│   ├── cisco_eox_webapp.py   # Flask web app (imports cisco_eox + cisco_swim)
│   └── requirements.txt      # Python dependencies
├── workflows/
│   ├── cisco_eox_lookup.md   # SOP for EOX data retrieval
│   └── cisco_swim_lookup.md  # SOP for SWIM software suggestion lookup
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

### `tools/cisco_eox_webapp.py` — Flask Web Application

Imports `cisco_eox` and `cisco_swim`. Serves a single-page application with three tabs.

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

**Starting the web app:**
```bash
cd tools
python cisco_eox_webapp.py    # runs on http://localhost:5001
```

**Limits:** `MAX_CONTENT_LENGTH = 50 MB`

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
