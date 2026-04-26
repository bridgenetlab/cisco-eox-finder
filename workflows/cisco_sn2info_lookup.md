# Workflow: Cisco SN2INFO Contract Coverage & PID Resolution

## Objective

Query the Cisco SN2INFO v2 API to resolve serial numbers to Product IDs and retrieve
contract coverage status (Active/Inactive) in a single API call.

---

## Compliance Rules

| Status | Condition |
|---|---|
| `Active` | Device is covered by an active service contract |
| `Inactive` | Service contract expired or not renewed |
| *(blank)* | SN not found in SN2INFO catalogue |

---

## Required Inputs

| Input | Required | Notes |
|---|---|---|
| Serial Number(s) | Yes | One or more, comma-separated for batch |

---

## Credentials

Same as EOX, SWIM, and PSIRT — stored in `.env` in the project root:

```
CISCO_CLIENT_ID=<your-client-id>
CISCO_CLIENT_SECRET=<your-client-secret>
```

The SN2INFO client imports `get_access_token()` from `cisco_eox.py` and shares the same
in-memory token cache.

---

## Tools

| Tool | Purpose |
|---|---|
| `tools/cisco_sn2info.py` | SN2INFO API client + CLI |
| `tools/cisco_eox_webapp.py` | Flask web app — Unified Report tab |

---

## Steps

### CLI

```bash
cd tools

# Single serial number
python cisco_sn2info.py --sn FOC10220LK9

# Multiple serial numbers
python cisco_sn2info.py --sn "SN1,SN2,SN3"

# Raw JSON output
python cisco_sn2info.py --sn FOC10220LK9 --json
```

### Web App — Unified Report

The SN2INFO lookup runs automatically as part of the **Unified Report** tab:

1. Start the app: `cd tools && python cisco_eox_webapp.py`
2. Open `http://localhost:5001`
3. Click the **Unified Report** tab
4. Upload a spreadsheet with a Serial Number column (and optionally PID and version columns)
5. The app auto-detects:
   - SN column (keywords: "serial number", "s/n", "serial\_no", "serial")
   - PID column (keywords: "product part", "pid", "part number", "model", "pn")
   - Version column and OS Type column
6. Click **Process File**
7. Download the enriched Excel file — it will contain four Coverage columns:
   - **Coverage Status** — `Active`, `Inactive`, or blank (not found)
   - **Coverage End Date** — YYYY-MM-DD contract end date
   - **Contract Number** — Cisco service contract number
   - **Service Level** — e.g. "SMARTNET 8X5XNBD"

---

## Expected Output (per serial number)

| Field | Description |
|---|---|
| `coverage_status` | `Active` or `Inactive` |
| `coverage_end_date` | YYYY-MM-DD date contract expires |
| `contract_number` | Cisco service contract number |
| `service_level` | Human-readable service tier description |
| `base_pid` | Base Product ID (from `base_pid_list`) |
| `orderable_pid` | Orderable PID (from `orderable_pid_list`) — preferred for SWIM lookup |

---

## API Constraints

- **Endpoint**: `GET /sn2info/v2/coverage/summary/serial_numbers/{SN1,SN2,...}`
- **Batch size**: Up to 20 SNs per request (conservative URL length limit)
- **Pagination**: API supports `page_index`; `get_coverage_summary()` walks all pages
- **Rate limits**: 5 calls/sec · 30 calls/min · 5,000 calls/day (shared with other Cisco APIs)
- **SN not in catalogue**: Returns no entry for that SN (treated as unknown, not an error)
- **Both PID and coverage returned** in a single call — no separate PID resolution endpoint needed

---

## Edge Cases

| Situation | Behaviour |
|---|---|
| SN not in catalogue | No entry returned; Coverage Status left blank |
| HTTP 400/404 | Error logged to stderr; SN gets empty coverage fields |
| HTTP 429 | Exponential backoff (1 s, 2 s, 4 s), up to 3 retries |
| Empty SN cell | Skipped silently; coverage fields left blank |
| Token expiry | Shared token cache auto-refreshes 60 s before expiry |

---

## Self-Improvement Log

_Append discoveries here — rate limits, unexpected response formats, SN format quirks, etc._
