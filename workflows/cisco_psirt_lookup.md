# Workflow: Cisco PSIRT openVuln Lookup

## Objective

Query the Cisco PSIRT openVuln API v2 to determine whether a network device's running software
version has any **Critical** security advisories, and evaluate compliance accordingly.

---

## Compliance Rules

| Status | Condition |
|---|---|
| `Non-Compliant` | One or more advisories at or above the severity threshold (default: Critical) |
| `Compliant` | No advisories meet the threshold for this OS type + version combination |
| `NA` | No software version was provided — advisory scan not performed |

The threshold is configurable via the `PSIRT_SEVERITY_THRESHOLD` environment variable (default:
`Critical`). Set to `High` to flag High and Critical advisories as Non-Compliant.

---

## Required Inputs

| Input | Required | Notes |
|---|---|---|
| OS Type | Yes | One of: `ios`, `iosxe`, `nxos`, `asa`, `ftd`, `fxos`, `fmc` |
| Software Version | Yes | Exact version string as reported by the device (e.g. `16.11.1`) |

**Important:** The PSIRT API does not support lookup by PID or serial number. You must provide
the OS type and the exact software version string.

---

## Credentials

Same as EOX and SWIM — stored in `.env` in the project root:

```
CISCO_CLIENT_ID=<your-client-id>
CISCO_CLIENT_SECRET=<your-client-secret>
```

Optional threshold override:
```
PSIRT_SEVERITY_THRESHOLD=High   # default: Critical
```

The PSIRT client imports `get_access_token()` from `cisco_eox.py` and shares the same in-memory
token cache.

---

## Tools

| Tool | Purpose |
|---|---|
| `tools/cisco_psirt.py` | PSIRT API client + CLI |
| `tools/cisco_eox_webapp.py` | Flask web app — PSIRT tab |

---

## Steps

### CLI

```bash
cd tools

# Single version lookup (human-readable)
python cisco_psirt.py --os-type iosxe --version 16.11.1

# Raw JSON output
python cisco_psirt.py --os-type iosxe --version 16.11.1 --json

# Filter display to Critical advisories only
python cisco_psirt.py --os-type iosxe --version 16.11.1 --severity Critical

# NX-OS example
python cisco_psirt.py --os-type nxos --version 9.3.6
```

### Web App — Single Search

1. Start the app: `cd tools && python cisco_eox_webapp.py`
2. Open `http://localhost:5001`
3. Click the **PSIRT** tab
4. Select the OS Type from the dropdown (e.g. IOS XE)
5. Enter the software version (e.g. `16.11.1`)
6. Click **Check Advisories**
7. Results show compliance badge, SIR counts, and a full advisory table with links

### Web App — Bulk Upload

1. Prepare a spreadsheet (`.xlsx` or `.csv`) with at least a software version column
   - Optionally include an OS Type column for per-row OS type
2. In the PSIRT tab, drag and drop the file or click to browse
3. The app auto-detects:
   - Version column (keywords: "current version", "sw version", "running version", etc.)
   - OS Type column (keywords: "os type", "software type", "platform", etc.)
4. If detection fails, use the column-mapping dropdowns and select a default OS type
5. Click **Process File**
6. Download the enriched Excel file — it will contain four new columns:
   - **PSIRT Compliance** — `Compliant`, `Non-Compliant`, or `NA`
   - **PSIRT Critical Advisories** — count of advisories at or above the threshold
   - **PSIRT Advisory IDs** — comma-separated advisory IDs (threshold+ only)
   - **PSIRT CVEs** — comma-separated CVE IDs (threshold+ only)

---

## Expected Output (per version query)

| Field | Description |
|---|---|
| `os_type` | OS type key (e.g. `iosxe`) |
| `version` | Version string as queried |
| `compliance` | `Compliant` or `Non-Compliant` |
| `advisories[].advisory_id` | Cisco advisory identifier (e.g. `cisco-sa-...`) |
| `advisories[].title` | Advisory title |
| `advisories[].sir` | Security Impact Rating: `Critical`, `High`, `Medium`, `Low` |
| `advisories[].cvss_score` | CVSS base score (0.0–10.0) |
| `advisories[].cves` | List of CVE identifiers |
| `advisories[].bug_ids` | List of Cisco Bug IDs |
| `advisories[].first_published` | ISO datetime of first publication |
| `advisories[].publication_url` | Link to the advisory on Cisco's security portal |

---

## API Constraints (Critical)

- **OS type required** — the PSIRT API has no PID-based lookup; you must supply the OS type
- **One call per unique (os_type, version) pair** — no batch endpoint
  - Example: 500-row spreadsheet with 200 unique versions → 200 sequential API calls
  - At roughly 0.2–0.5 s per call, expect 1–2 minutes for large uploads
- **Rate limits:** 5 calls/sec · 30 calls/min · 5,000 calls/day
- **Version must be exact** — minor formatting differences (e.g. `16.11.01` vs `16.11.1`) may
  return different result sets from the API
- **Empty advisory list ≠ error** — if a version is not in the PSIRT catalogue, the API returns
  an empty list, which is treated as `Compliant`

---

## Supported OS Types

| Key | Display |
|---|---|
| `ios` | IOS |
| `iosxe` | IOS XE |
| `nxos` | NX-OS |
| `asa` | ASA |
| `ftd` | FTD |
| `fxos` | FXOS |
| `fmc` | FMC |

---

## Edge Cases

| Situation | Behaviour |
|---|---|
| Version not in PSIRT catalogue | Empty advisory list → `Compliant` |
| HTTP 400/404 | Error logged to stderr; row gets empty compliance fields |
| HTTP 429 | Exponential backoff (1 s, 2 s, 4 s), up to 3 retries |
| Empty version cell | `PSIRT Compliance = NA`; advisory columns left blank |
| OS type column value not recognised | Falls back to `default_os_type` (default: `iosxe`) |
| No OS type column in bulk file | All rows use `default_os_type` |
| Token expiry | Shared token cache auto-refreshes 60 s before expiry |

---

## Self-Improvement Log

_Append discoveries here — rate limits, unexpected response formats, version string quirks, etc._
