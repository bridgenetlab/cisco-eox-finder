# Workflow: Cisco Bug API v2.0 Lookup

## Objective

Query the Cisco Bug API v2.0 to find known open defects (CSCxxx IDs) for a device's
Product ID (PID) and optionally its running software version, and evaluate compliance.

---

## Compliance Rules

| Status | Condition |
|---|---|
| `Non-Compliant` | One or more Open bugs at or above the severity threshold |
| `Compliant` | No Open bugs meet the threshold (including no bugs found) |
| `NA` | No PID available — bug scan not performed |

The threshold is numeric: 1=Critical, 2=High, 3=Moderate, 4=Minor (lower = more severe).
Default threshold is `2` (flag Critical + High bugs as Non-Compliant). Only **Open** bugs
(`status = "O"`) count for compliance; Fixed, Terminated, or Duplicate bugs are ignored.

---

## Required Inputs

| Input | Required | Notes |
|---|---|---|
| Base PID | Yes | Single exact PID — no wildcards, no commas |
| Software Version | No | If provided, narrows results to bugs affecting that release specifically |

---

## Credentials

Same as all other Cisco APIs — stored in `.env` in the project root:

```
CISCO_CLIENT_ID=<your-client-id>
CISCO_CLIENT_SECRET=<your-client-secret>
```

Optional override:
```
BUG_SEVERITY_THRESHOLD=1   # default 2; set 1 for Critical-only, 3 to include Moderate
```

The Bug API client imports `get_access_token()` from `cisco_eox.py` and shares the same
in-memory token cache.

---

## Tools

| Tool | Purpose |
|---|---|
| `tools/cisco_bug.py` | Bug API v2.0 client + CLI |
| `tools/cisco_eox_webapp.py` | Flask web app — Bugs tab + Unified Report |

---

## Steps

### CLI

```bash
cd tools

# Single PID (all bugs)
python cisco_bug.py --pid WS-C3560-48PS-S

# PID + version (bugs affecting that specific release)
python cisco_bug.py --pid WS-C3560-48PS-S --version "12.2(25)SEE2"

# Raw JSON output
python cisco_bug.py --pid WS-C3560-48PS-S --json

# Batch file (one pid or pid:version per line, # for comments)
python cisco_bug.py --batch-file devices.txt
```

Batch file format:
```
WS-C3560-48PS-S
ASR-903:16.11.1
# comments are ignored
```

### Web App — Bugs Tab

1. Start the app: `cd tools && python cisco_eox_webapp.py`
2. Open `http://localhost:5001`
3. Click the **Bugs** tab

**Single search:**
- Enter a Base PID (required) and optional Software Version
- Click **Find Bugs**
- Results show compliance badge, open/total counts, and a table with severity, Bug ID
  (linked to Cisco Bug Search), headline, status, affected releases, and fixed releases

**Bulk upload:**
1. Drop an Excel/CSV file onto the upload zone
2. App auto-detects PID column (keywords: "product part", "pid", "part number", "model")
   and optional version column (keywords: "current version", "sw version", "firmware")
3. If detection fails, select columns manually from the mapping dropdowns
4. Click **Process File**
5. Download the enriched Excel with 4 new Bug columns

### Web App — Unified Report

The Bug lookup runs automatically as the 5th step in the Unified Report:
1. Click the **Unified Report** tab
2. Upload a spreadsheet with at least a PID or Serial Number column
3. All five lookups run in sequence: EOX → Coverage → SWIM → PSIRT → Bug
4. The enriched Excel will contain 4 new Bug columns (in purple)

---

## Expected Output (per device/row)

| Field | Description |
|---|---|
| `Bug Compliance` | `Compliant`, `Non-Compliant`, or `NA` |
| `Bug Open Count` | Total number of open bugs found |
| `Bug IDs` | Comma-separated CSCxxx IDs of open threshold-severity bugs |
| `Bug Fixed Count` | Count of open bugs at threshold severity (used for dashboard) |

---

## API Constraints

- **Base URL**: `https://apix.cisco.com/bug/v2.0/bugs`
- **Endpoints used**:
  - `GET /base_pid/{pid}` — all bugs for a PID
  - `GET /base_pid/{pid}/affected_releases/{version}` — bugs for a specific PID + version
- **One PID per request** — no batch endpoint
- **Pagination**: 10 results per page; client walks all pages automatically
- **Rate limits**: shared exponential backoff on 429 (1s, 2s, 4s, up to 3 retries)
- **400/404**: treated as no results (not an error) → `Compliant`
- **Version string format**: URL-encoded; use exact string as reported by device

---

## Edge Cases

| Situation | Behaviour |
|---|---|
| PID not in Bug catalogue | Empty bug list → `Compliant` |
| Version not found in affected_releases | Client falls back to `base_pid` endpoint (all bugs for PID) |
| HTTP 400/404 | Logged to stderr; row gets empty Bug columns (treated as Compliant) |
| HTTP 429 | Exponential backoff, up to 3 retries |
| No PID in row | `Bug Compliance = NA`, other Bug columns left empty |
| All bugs are Fixed | `Compliant` (only Open bugs count) |
| Empty PID cell | Skipped silently; Bug columns left blank |
| Token expiry | Shared token cache auto-refreshes 60s before expiry |

---

## Self-Improvement Log

_Append discoveries here — rate limits, unexpected response formats, version string quirks, etc._
