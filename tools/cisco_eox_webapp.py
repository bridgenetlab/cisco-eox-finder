"""
Cisco EOX Finder — Flask Web App
- Single lookup by Product ID / Serial Number
- Bulk Excel upload: auto-detects "Product Part" (PID) and "Serial Number" columns,
  enriches every row with EOX dates + compliance status, lets you download enriched Excel.

Run:
  cd tools && python cisco_eox_webapp.py
  Open http://localhost:5001
"""

import io
import pickle
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, render_template_string, request, send_file

sys.path.insert(0, str(Path(__file__).parent))
import cisco_eox
import cisco_psirt
import cisco_swim

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# ── SQLite job store ─────────────────────────────────────────────────────────
_DB_PATH = Path(__file__).parent / "eox_jobs.db"
_JOB_TTL = 86400  # 24 hours


def _db():
    conn = sqlite3.connect(_DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS jobs "
        "(job_id TEXT PRIMARY KEY, data BLOB NOT NULL, created_at INTEGER NOT NULL)"
    )
    conn.commit()
    return conn


def _store_job(job_id: str, df: pd.DataFrame) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO jobs (job_id, data, created_at) VALUES (?, ?, ?)",
            (job_id, pickle.dumps(df), int(time.time())),
        )
        conn.execute("DELETE FROM jobs WHERE created_at < ?", (int(time.time()) - _JOB_TTL,))


def _load_job(job_id: str) -> pd.DataFrame | None:
    with _db() as conn:
        row = conn.execute("SELECT data FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    return pickle.loads(row[0]) if row else None

# ── Column-name detection ────────────────────────────────────────────────────
PID_KEYWORDS = ["product part", "product_part", "productpart", "pid",
                "part number", "part_number", "partnumber", "part no", "part_no"]
SN_KEYWORDS  = ["serial number", "serial_number", "serialnumber",
                "serial no", "serial_no", "s/n", " sn"]

def _find_col(df: pd.DataFrame, keywords: list[str]) -> str | None:
    for col in df.columns:
        cl = col.strip().lower()
        if any(kw in cl for kw in keywords):
            return col
    return None

# ── EOX date columns to add ──────────────────────────────────────────────────
EOX_COLS = [
    ("EOX End of Sale",              "end_of_sale"),
    ("EOX End of SW Maintenance",    "end_of_sw_maintenance"),
    ("EOX End of Security Support",  "end_of_security_support"),
    ("EOX End of Service Contract",  "end_of_service_contract"),
    ("EOX Last Date of Support",     "last_date_of_support"),
    ("EOX Compliance",               "compliance_label"),
    ("EOX Migration PID",            "migration_product_id"),
]

# ── SWIM columns and version-column detection ────────────────────────────────
SWIM_VERSION_KEYWORDS = [
    "current version", "current_version", "sw version", "software version",
    "running version", "ios version", "firmware",
]

SWIM_COLS = [
    ("SWIM Suggested Release", "suggested_release"),
    ("SWIM Lifecycle",         "lifecycle"),
    ("SWIM Compliance",        "swim_compliance"),
]

# ── PSIRT columns and OS-type-column detection ───────────────────────────────
OS_TYPE_KEYWORDS = ["os type", "os_type", "software type", "software_type", "platform"]

PSIRT_COLS = [
    ("PSIRT Compliance",          "compliance"),
    ("PSIRT Critical Advisories", "critical_count"),
    ("PSIRT Advisory IDs",        "advisory_ids"),
    ("PSIRT CVEs",               "cves"),
]

# ── Batched lookups ──────────────────────────────────────────────────────────
def _build_pid_lookup(pids: list[str]) -> dict[str, dict]:
    """Query EOX API for a list of unique PIDs (batched 20 at a time)."""
    lookup: dict[str, dict] = {}
    batch_size = 20
    for i in range(0, len(pids), batch_size):
        batch = [p for p in pids[i:i + batch_size] if p]
        if not batch:
            continue
        result = cisco_eox.query_by_product_id(",".join(batch))
        for rec in result.get("records", []):
            if "error" not in rec:
                lookup[rec["product_id"].upper()] = rec
    return lookup


def _build_sn_lookup(sns: list[str]) -> dict[str, dict]:
    """Query EOX API for a list of unique SNs (batched 20 at a time, mapped by position)."""
    lookup: dict[str, dict] = {}
    batch_size = 20
    for i in range(0, len(sns), batch_size):
        batch = [s for s in sns[i:i + batch_size] if s]
        if not batch:
            continue
        result = cisco_eox.query_by_serial_number(",".join(batch))
        for j, rec in enumerate(result.get("records", [])):
            if j < len(batch) and "error" not in rec:
                lookup[batch[j].upper()] = rec
    return lookup

def _build_swim_lookup(pids: list[str]) -> dict[str, dict]:
    """Query SWIM API for unique PIDs one at a time (no batch support in the API)."""
    lookup: dict[str, dict] = {}
    for pid in pids:
        if not pid:
            continue
        try:
            rec = cisco_swim.get_suggested_release(pid)
            lookup[pid.upper()] = rec or {}
        except Exception as exc:
            print(f"SWIM lookup failed for {pid}: {exc}", file=sys.stderr)
            lookup[pid.upper()] = {}
    return lookup


def _build_psirt_lookup(
    pairs: list[tuple[str, str]],
) -> dict[tuple[str, str], dict]:
    """Query PSIRT API for unique (os_type, version) pairs one at a time."""
    lookup: dict[tuple[str, str], dict] = {}
    for os_type, version in pairs:
        key = (os_type.lower(), version.lower())
        if key in lookup:
            continue
        try:
            rec = cisco_psirt.get_psirt_summary(os_type, version)
            lookup[key] = rec or {}
        except Exception as exc:
            print(f"PSIRT lookup failed for {os_type}/{version}: {exc}", file=sys.stderr)
            lookup[key] = {}
    return lookup

# ── HTML ─────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco EOX Finder</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: #0d1117; color: #e6edf3; min-height: 100vh; padding: 2rem 1rem;
}

header { max-width: 1200px; margin: 0 auto 1.5rem; }
.logo { font-size: 1.5rem; font-weight: 700; color: #1f6feb; letter-spacing: -0.5px; }
.logo span { color: #58a6ff; }
header p { font-size: 0.875rem; color: #8b949e; margin-top: 0.25rem; }

/* Tabs */
.tabs { max-width: 1200px; margin: 0 auto 1.5rem; display: flex; gap: 0.5rem; border-bottom: 1px solid #30363d; }
.tab-btn {
  padding: 0.6rem 1.2rem; background: none; border: none; border-bottom: 2px solid transparent;
  color: #8b949e; font-size: 0.9rem; font-weight: 600; cursor: pointer; margin-bottom: -1px;
  transition: color 0.2s, border-color 0.2s;
}
.tab-btn:hover { color: #c9d1d9; }
.tab-btn.active { color: #58a6ff; border-bottom-color: #58a6ff; }

.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* Cards */
.card {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 1.5rem; max-width: 1200px; margin: 0 auto 1.5rem;
}
.card h2 { font-size: 1rem; font-weight: 600; color: #c9d1d9; margin-bottom: 1rem; }

.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
@media (max-width: 600px) { .form-row { grid-template-columns: 1fr; } }

label {
  display: block; font-size: 0.8rem; font-weight: 600; color: #8b949e;
  margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 0.5px;
}
input[type="text"], input[type="file"] {
  width: 100%; padding: 0.6rem 0.75rem; background: #0d1117;
  border: 1px solid #30363d; border-radius: 6px; color: #e6edf3;
  font-size: 0.9rem; font-family: "SF Mono", "Fira Code", monospace; transition: border-color 0.2s;
}
input[type="text"]:focus, input[type="file"]:focus {
  outline: none; border-color: #1f6feb; box-shadow: 0 0 0 3px rgba(31,111,235,0.15);
}
input[type="file"] { font-family: inherit; cursor: pointer; }
.hint { font-size: 0.75rem; color: #6e7681; margin-top: 0.3rem; }

.btn-row { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }
.btn-primary {
  padding: 0.6rem 1.5rem; background: #1f6feb; color: #fff;
  border: none; border-radius: 6px; font-size: 0.9rem; font-weight: 600;
  cursor: pointer; transition: background 0.2s;
}
.btn-primary:hover { background: #388bfd; }
.btn-primary:disabled { background: #30363d; color: #6e7681; cursor: not-allowed; }
.btn-secondary {
  padding: 0.6rem 1rem; background: transparent; color: #8b949e;
  border: 1px solid #30363d; border-radius: 6px; font-size: 0.85rem; cursor: pointer;
}
.btn-secondary:hover { border-color: #8b949e; color: #e6edf3; }
.btn-green {
  padding: 0.6rem 1.25rem; background: #238636; color: #fff;
  border: none; border-radius: 6px; font-size: 0.85rem; font-weight: 600; cursor: pointer;
  text-decoration: none; display: inline-block;
}
.btn-green:hover { background: #2ea043; }

/* Drop zone */
.drop-zone {
  border: 2px dashed #30363d; border-radius: 8px; padding: 2rem;
  text-align: center; cursor: pointer; transition: border-color 0.2s, background 0.2s;
  margin-bottom: 1rem;
}
.drop-zone:hover, .drop-zone.dragover { border-color: #1f6feb; background: rgba(31,111,235,0.05); }
.drop-zone p { color: #8b949e; font-size: 0.9rem; margin-bottom: 0.5rem; }
.drop-zone .drop-icon { font-size: 2rem; margin-bottom: 0.5rem; }

/* Progress */
.progress-wrap { margin-bottom: 1rem; display: none; }
.progress-bar-bg {
  height: 6px; background: #21262d; border-radius: 3px; overflow: hidden; margin-bottom: 0.4rem;
}
.progress-bar-fill { height: 100%; background: #1f6feb; border-radius: 3px; transition: width 0.3s; }
.progress-text { font-size: 0.8rem; color: #8b949e; }

/* Status */
.status-msg { font-size: 0.85rem; color: #8b949e; }

/* Summary pills */
.summary-bar {
  display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem;
  max-width: 1200px; margin-left: auto; margin-right: auto;
}
.pill {
  padding: 0.4rem 1rem; border-radius: 20px; font-size: 0.8rem; font-weight: 700;
}
.pill-total    { background: rgba(88,166,255,0.1);  color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }
.pill-c        { background: rgba(63,185,80,0.1);   color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
.pill-w        { background: rgba(227,179,65,0.1);  color: #e3b341; border: 1px solid rgba(227,179,65,0.3); }
.pill-nc       { background: rgba(248,81,73,0.1);   color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.pill-uk       { background: rgba(110,118,129,0.1); color: #8b949e; border: 1px solid rgba(110,118,129,0.3); }

/* Table */
.table-wrap {
  max-width: 1200px; margin: 0 auto 1.5rem;
  overflow-x: auto; border: 1px solid #30363d; border-radius: 8px;
}
table {
  width: 100%; border-collapse: collapse; font-size: 0.8rem; white-space: nowrap;
}
thead th {
  background: #161b22; color: #8b949e; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.4px; padding: 0.6rem 0.75rem; text-align: left;
  border-bottom: 1px solid #30363d; position: sticky; top: 0; z-index: 1;
}
thead th.eox-col { color: #58a6ff; }
tbody tr { border-bottom: 1px solid #21262d; }
tbody tr:hover { background: rgba(255,255,255,0.02); }
tbody tr:last-child { border-bottom: none; }
td { padding: 0.55rem 0.75rem; color: #c9d1d9; max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
td.mono { font-family: "SF Mono", "Fira Code", monospace; color: #58a6ff; }
td.na { color: #484f58; font-style: italic; }

.badge-sm {
  padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: 700; white-space: nowrap;
}
.badge-sm-nc { background: rgba(248,81,73,0.15);  color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.badge-sm-w  { background: rgba(227,179,65,0.15); color: #e3b341; border: 1px solid rgba(227,179,65,0.3); }
.badge-sm-c  { background: rgba(63,185,80,0.15);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
.badge-sm-uk { background: rgba(110,118,129,0.15); color: #8b949e; border: 1px solid rgba(110,118,129,0.3); }

/* Pagination */
.pagination { display: flex; gap: 0.5rem; align-items: center; justify-content: center; padding: 1rem; }
.page-btn {
  padding: 0.35rem 0.75rem; background: #161b22; border: 1px solid #30363d;
  border-radius: 6px; color: #8b949e; font-size: 0.8rem; cursor: pointer;
}
.page-btn:hover { border-color: #58a6ff; color: #58a6ff; }
.page-btn.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
.page-info-txt { font-size: 0.8rem; color: #6e7681; }

/* Single-search results */
#results { max-width: 1200px; margin: 0 auto; }
.result-section { margin-bottom: 1.5rem; }
.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
.result-header h3 { font-size: 0.9rem; color: #8b949e; }
.result-header .page-info { font-size: 0.8rem; color: #6e7681; }

.eox-card {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 1.25rem; margin-bottom: 0.75rem;
}
.eox-card.noncompliant { border-left: 4px solid #f85149; }
.eox-card.warning      { border-left: 4px solid #e3b341; }
.eox-card.compliant    { border-left: 4px solid #3fb950; }
.eox-card.unknown      { border-left: 4px solid #6e7681; }
.eox-card.error-card   { border-left: 4px solid #6e7681; }
.eox-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
.eox-pid { font-family: "SF Mono", "Fira Code", monospace; font-size: 1.05rem; font-weight: 700; color: #58a6ff; }
.eox-name { font-size: 0.85rem; color: #8b949e; margin-top: 0.2rem; }
.badge { padding: 0.3rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 700; white-space: nowrap; }
.badge-noncompliant { background: rgba(248,81,73,0.15);  color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.badge-warning      { background: rgba(227,179,65,0.15); color: #e3b341; border: 1px solid rgba(227,179,65,0.3); }
.badge-compliant    { background: rgba(63,185,80,0.15);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
.badge-unknown      { background: rgba(110,118,129,0.15); color: #8b949e; border: 1px solid rgba(110,118,129,0.3); }
.days-remaining { font-size: 0.75rem; color: #6e7681; margin-top: 0.1rem; }
.eox-dates { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.6rem; margin-bottom: 0.75rem; }
.date-label { font-size: 0.7rem; color: #6e7681; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 0.15rem; }
.date-value { font-family: "SF Mono", "Fira Code", monospace; font-size: 0.85rem; color: #c9d1d9; }
.date-value.na { color: #484f58; }
.migration-section { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 0.75rem; font-size: 0.85rem; }
.migration-label { font-size: 0.7rem; color: #6e7681; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 0.4rem; }
.migration-pid { font-family: "SF Mono", "Fira Code", monospace; color: #58a6ff; font-weight: 600; margin-right: 0.5rem; }
.migration-info { color: #8b949e; }
.migration-url a { color: #58a6ff; font-size: 0.8rem; text-decoration: none; }
.migration-url a:hover { text-decoration: underline; }
.error-msg { color: #f85149; font-size: 0.9rem; padding: 1rem; background: rgba(248,81,73,0.08); border-radius: 6px; border: 1px solid rgba(248,81,73,0.2); }
.bulletin-link a { color: #8b949e; font-size: 0.8rem; text-decoration: none; }
.bulletin-link a:hover { color: #58a6ff; }
.loading { text-align: center; padding: 2rem; color: #8b949e; font-size: 0.9rem; }
.spinner { display: inline-block; width: 18px; height: 18px; border: 2px solid #30363d; border-top-color: #1f6feb; border-radius: 50%; animation: spin 0.6s linear infinite; margin-right: 0.5rem; vertical-align: middle; }
@keyframes spin { to { transform: rotate(360deg); } }
.no-results { text-align: center; color: #6e7681; padding: 2rem; font-size: 0.9rem; }

/* Search history */
#searchHistory { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem; align-items: center; }
.history-chip {
  padding: 0.25rem 0.75rem; background: rgba(88,166,255,0.08); color: #58a6ff;
  border: 1px solid rgba(88,166,255,0.25); border-radius: 20px;
  font-size: 0.75rem; font-family: "SF Mono","Fira Code",monospace; cursor: pointer;
}
.history-chip:hover { background: rgba(88,166,255,0.18); }

/* Column mapping */
#colMappingWrap {
  background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
  padding: 1rem; margin-bottom: 1rem;
}
#colMappingWrap p { font-size: 0.85rem; color: #8b949e; margin-bottom: 0.75rem; }
select {
  width: 100%; padding: 0.6rem 0.75rem; background: #0d1117;
  border: 1px solid #30363d; border-radius: 6px; color: #e6edf3;
  font-size: 0.9rem; cursor: pointer;
}
select:focus { outline: none; border-color: #1f6feb; }

/* Compliance chart */
#bulkChartWrap { max-width: 300px; margin: 0 auto 1.5rem; display: none; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
</head>
<body>

<header>
  <div class="logo">Cisco <span>EOX</span> Finder</div>
  <p>End-of-Life · SWIM · PSIRT Security — Cisco APIs</p>
</header>

<div class="tabs">
  <button class="tab-btn active" data-tab="single">Single Search</button>
  <button class="tab-btn" data-tab="bulk">Bulk Excel Upload</button>
  <button class="tab-btn" data-tab="swim">SWIM</button>
  <button class="tab-btn" data-tab="psirt">PSIRT</button>
</div>

<!-- ── Single Search ── -->
<div id="tab-single" class="tab-panel active">
  <div class="card">
    <h2>Search by Product ID or Serial Number</h2>
    <form id="searchForm">
      <div class="form-row">
        <div>
          <label for="pid">Product ID</label>
          <input type="text" id="pid" name="pid" placeholder="e.g. WS-C2960X-24TS-L" autocomplete="off">
          <div class="hint">Wildcards (WS-C2960*) and comma-separated (up to 20)</div>
        </div>
        <div>
          <label for="sn">Serial Number</label>
          <input type="text" id="sn" name="sn" placeholder="e.g. FHH12345678" autocomplete="off">
          <div class="hint">Comma-separated (up to 20)</div>
        </div>
      </div>
      <div class="btn-row">
        <button type="submit" id="searchBtn" class="btn-primary">Search EOX</button>
        <button type="button" id="clearBtn" class="btn-secondary">Clear</button>
        <span id="searchStatus" class="status-msg"></span>
      </div>
      <div id="searchHistory"></div>
    </form>
  </div>
  <div id="results"></div>
</div>

<!-- ── Bulk Upload ── -->
<div id="tab-bulk" class="tab-panel">
  <div class="card">
    <h2>Bulk Excel Upload</h2>

    <div class="drop-zone" id="dropZone">
      <div class="drop-icon">📊</div>
      <p>Drag &amp; drop your Excel file here, or click to browse</p>
      <p style="font-size:0.75rem;color:#6e7681">.xlsx / .csv · auto-detects "Product Part" and "Serial Number" columns</p>
      <input type="file" id="fileInput" accept=".xlsx,.xls,.csv" style="display:none">
    </div>

    <div id="detectedCols" style="display:none;margin-bottom:1rem;">
      <span style="font-size:0.8rem;color:#8b949e">Detected columns: </span>
      <span id="colPid" style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span style="font-size:0.8rem;color:#6e7681"> · </span>
      <span id="colSn"  style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
    </div>

    <div class="progress-wrap" id="progressWrap">
      <div class="progress-bar-bg"><div class="progress-bar-fill" id="progressFill" style="width:0%"></div></div>
      <div class="progress-text" id="progressText">Processing…</div>
    </div>

    <div id="colMappingWrap" style="display:none">
      <p>Could not auto-detect columns. Select the correct ones below:</p>
      <div class="form-row">
        <div>
          <label>Product ID Column</label>
          <select id="manualPidSel"></select>
        </div>
        <div>
          <label>Serial Number Column</label>
          <select id="manualSnSel"></select>
        </div>
      </div>
      <div class="btn-row" style="margin-top:0.75rem">
        <button class="btn-primary" onclick="resubmitWithMapping()">Process with Selected Columns</button>
      </div>
    </div>

    <div class="btn-row">
      <button id="uploadBtn" class="btn-primary" disabled>Process File</button>
      <button id="clearUploadBtn" class="btn-secondary">Clear</button>
      <span id="uploadStatus" class="status-msg"></span>
    </div>
  </div>

  <!-- Summary + Chart + Download -->
  <div id="bulkSummaryBar" class="summary-bar" style="display:none"></div>
  <div id="bulkChartWrap"><canvas id="complianceChart"></canvas></div>

  <div id="bulkDownloadBar" style="max-width:1200px;margin:0 auto 1rem;display:none">
    <a id="downloadLink" class="btn-green" href="#">⬇ Download Enriched Excel</a>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + EOX dates</span>
  </div>

  <div id="bulkTableWrap" class="table-wrap" style="display:none">
    <table id="bulkTable">
      <thead id="bulkThead"></thead>
      <tbody id="bulkTbody"></tbody>
    </table>
    <div class="pagination" id="pagination"></div>
  </div>
</div>

<!-- ── SWIM Tab ── -->
<div id="tab-swim" class="tab-panel">

  <!-- Single search -->
  <div class="card">
    <h2>SWIM — Software Image Lookup</h2>
    <form id="swimSearchForm">
      <div class="form-row" style="grid-template-columns:1fr">
        <div>
          <label for="swimPid">Product ID</label>
          <input type="text" id="swimPid" name="swimPid" placeholder="e.g. ASR-903" autocomplete="off">
          <div class="hint">One PID at a time — SWIM API does not support batching or wildcards</div>
        </div>
      </div>
      <div class="btn-row">
        <button type="submit" id="swimSearchBtn" class="btn-primary">Get Suggested Software</button>
        <button type="button" id="swimClearBtn" class="btn-secondary">Clear</button>
        <span id="swimSearchStatus" class="status-msg"></span>
      </div>
    </form>
  </div>
  <div id="swimResults"></div>

  <!-- Bulk upload -->
  <div class="card">
    <h2>SWIM Bulk Upload</h2>
    <div class="drop-zone" id="swimDropZone">
      <div class="drop-icon">💿</div>
      <p>Drag &amp; drop your Excel file here, or click to browse</p>
      <p style="font-size:0.75rem;color:#6e7681">.xlsx / .csv · detects "Product Part" and optionally "Current Version"</p>
      <input type="file" id="swimFileInput" accept=".xlsx,.xls,.csv" style="display:none">
    </div>
    <div id="swimDetectedCols" style="display:none;margin-bottom:1rem;">
      <span style="font-size:0.8rem;color:#8b949e">Detected columns: </span>
      <span id="swimColPid"     style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span style="font-size:0.8rem;color:#6e7681"> · </span>
      <span id="swimColVersion" style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
    </div>
    <div class="progress-wrap" id="swimProgressWrap">
      <div class="progress-bar-bg"><div class="progress-bar-fill" id="swimProgressFill" style="width:0%"></div></div>
      <div class="progress-text" id="swimProgressText">Processing…</div>
    </div>
    <div id="swimColMappingWrap" style="display:none">
      <p style="font-size:0.85rem;color:#8b949e;margin-bottom:0.75rem">Could not auto-detect columns. Select the correct ones below:</p>
      <div class="form-row">
        <div><label>Product ID Column</label><select id="swimManualPidSel"></select></div>
        <div><label>Current Version Column (optional)</label><select id="swimManualVersionSel"></select></div>
      </div>
      <div class="btn-row" style="margin-top:0.75rem">
        <button class="btn-primary" onclick="swimResubmitWithMapping()">Process with Selected Columns</button>
      </div>
    </div>
    <div class="btn-row">
      <button id="swimUploadBtn" class="btn-primary" disabled>Process File</button>
      <button id="swimClearUploadBtn" class="btn-secondary">Clear</button>
      <span id="swimUploadStatus" class="status-msg"></span>
    </div>
  </div>

  <div id="swimSummaryBar"  class="summary-bar"                        style="display:none"></div>
  <div id="swimDownloadBar" style="max-width:1200px;margin:0 auto 1rem;display:none">
    <a id="swimDownloadLink" class="btn-green" href="#">⬇ Download Enriched Excel</a>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + SWIM suggested release + compliance</span>
  </div>
  <div id="swimTableWrap" class="table-wrap" style="display:none">
    <table id="swimTable"><thead id="swimThead"></thead><tbody id="swimTbody"></tbody></table>
    <div class="pagination" id="swimPagination"></div>
  </div>
</div>

<!-- ── PSIRT Tab ── -->
<div id="tab-psirt" class="tab-panel">

  <!-- Single search -->
  <div class="card">
    <h2>PSIRT — Security Advisory Lookup</h2>
    <form id="psirtSearchForm">
      <div class="form-row">
        <div>
          <label for="psirtOsType">OS Type</label>
          <select id="psirtOsType">
            <option value="iosxe">IOS XE</option>
            <option value="ios">IOS</option>
            <option value="nxos">NX-OS</option>
            <option value="asa">ASA</option>
            <option value="ftd">FTD</option>
            <option value="fxos">FXOS</option>
            <option value="fmc">FMC</option>
          </select>
        </div>
        <div>
          <label for="psirtVersion">Software Version</label>
          <input type="text" id="psirtVersion" placeholder="e.g. 16.11.1" autocomplete="off">
          <div class="hint">Exact version string as reported by the device</div>
        </div>
      </div>
      <div class="btn-row">
        <button type="submit" id="psirtSearchBtn" class="btn-primary">Check Advisories</button>
        <button type="button" id="psirtClearBtn" class="btn-secondary">Clear</button>
        <span id="psirtSearchStatus" class="status-msg"></span>
      </div>
    </form>
  </div>
  <div id="psirtResults"></div>

  <!-- Bulk upload -->
  <div class="card">
    <h2>PSIRT Bulk Upload</h2>
    <div class="drop-zone" id="psirtDropZone">
      <div class="drop-icon">🔐</div>
      <p>Drag &amp; drop your Excel file here, or click to browse</p>
      <p style="font-size:0.75rem;color:#6e7681">.xlsx / .csv · detects "Current Version" and optionally "OS Type" columns</p>
      <input type="file" id="psirtFileInput" accept=".xlsx,.xls,.csv" style="display:none">
    </div>
    <div id="psirtDetectedCols" style="display:none;margin-bottom:1rem;">
      <span style="font-size:0.8rem;color:#8b949e">Detected columns: </span>
      <span id="psirtColVersion" style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span style="font-size:0.8rem;color:#6e7681"> · </span>
      <span id="psirtColOsType" style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
    </div>
    <div class="progress-wrap" id="psirtProgressWrap">
      <div class="progress-bar-bg"><div class="progress-bar-fill" id="psirtProgressFill" style="width:0%"></div></div>
      <div class="progress-text" id="psirtProgressText">Processing…</div>
    </div>
    <div id="psirtColMappingWrap" style="display:none">
      <p style="font-size:0.85rem;color:#8b949e;margin-bottom:0.75rem">Could not auto-detect version column. Select below:</p>
      <div class="form-row">
        <div><label>Software Version Column</label><select id="psirtManualVersionSel"></select></div>
        <div><label>OS Type Column (optional)</label><select id="psirtManualOsTypeSel"></select></div>
      </div>
      <div style="margin-bottom:0.75rem">
        <label>Default OS Type (used when no OS Type column)</label>
        <select id="psirtDefaultOsTypeSel">
          <option value="iosxe">IOS XE</option>
          <option value="ios">IOS</option>
          <option value="nxos">NX-OS</option>
          <option value="asa">ASA</option>
          <option value="ftd">FTD</option>
          <option value="fxos">FXOS</option>
          <option value="fmc">FMC</option>
        </select>
      </div>
      <div class="btn-row">
        <button class="btn-primary" onclick="psirtResubmitWithMapping()">Process with Selected Columns</button>
      </div>
    </div>
    <div class="btn-row">
      <button id="psirtUploadBtn" class="btn-primary" disabled>Process File</button>
      <button id="psirtClearUploadBtn" class="btn-secondary">Clear</button>
      <span id="psirtUploadStatus" class="status-msg"></span>
    </div>
  </div>

  <div id="psirtSummaryBar"  class="summary-bar"                        style="display:none"></div>
  <div id="psirtDownloadBar" style="max-width:1200px;margin:0 auto 1rem;display:none">
    <a id="psirtDownloadLink" class="btn-green" href="#">⬇ Download Enriched Excel</a>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + PSIRT advisory data</span>
  </div>
  <div id="psirtTableWrap" class="table-wrap" style="display:none">
    <table id="psirtTable"><thead id="psirtThead"></thead><tbody id="psirtTbody"></tbody></table>
    <div class="pagination" id="psirtPagination"></div>
  </div>
</div>

<script>
// ── Tab switching ────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ── Single Search ────────────────────────────────────────────────────────────
const searchForm   = document.getElementById('searchForm');
const resultsDiv   = document.getElementById('results');
const searchStatus = document.getElementById('searchStatus');
const searchBtn    = document.getElementById('searchBtn');

document.getElementById('clearBtn').addEventListener('click', () => {
  document.getElementById('pid').value = '';
  document.getElementById('sn').value = '';
  resultsDiv.innerHTML = '';
  searchStatus.textContent = '';
});

searchForm.addEventListener('submit', async e => {
  e.preventDefault();
  const pid = document.getElementById('pid').value.trim();
  const sn  = document.getElementById('sn').value.trim();
  if (!pid && !sn) { searchStatus.textContent = 'Enter a Product ID or Serial Number.'; return; }
  searchBtn.disabled = true;
  searchStatus.textContent = '';
  resultsDiv.innerHTML = '<div class="loading"><span class="spinner"></span>Querying Cisco EOX API…</div>';
  try {
    const resp = await fetch('/search', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pid, sn}),
    });
    const data = await resp.json();
    if (!resp.ok) { resultsDiv.innerHTML = `<div class="error-msg">Error: ${data.error || 'Unknown'}</div>`; return; }
    renderSingleResults(data.results);
    addToHistory(pid, sn);
  } catch(err) {
    resultsDiv.innerHTML = `<div class="error-msg">Network error: ${err.message}</div>`;
  } finally { searchBtn.disabled = false; }
});

function fmtDate(v) {
  return (!v || !v.trim()) ? '<span class="date-value na">N/A</span>' : `<span class="date-value">${v}</span>`;
}
function complianceBadge(c) {
  const m = {compliant:'badge-compliant',warning:'badge-warning',noncompliant:'badge-noncompliant',unknown:'badge-unknown'};
  return `<span class="badge ${m[c.status]||'badge-unknown'}">${c.label}</span>`;
}
function daysNote(c) {
  if (c.days_remaining === null) return '';
  return c.days_remaining < 0
    ? `<div class="days-remaining">Expired ${Math.abs(c.days_remaining)} days ago</div>`
    : `<div class="days-remaining">${c.days_remaining} days remaining</div>`;
}
function renderRecord(rec) {
  if (rec.error) return `<div class="eox-card error-card"><div class="error-msg">Query: <code>${rec.query}</code> — ${rec.error}</div></div>`;
  const c = rec.compliance;
  return `<div class="eox-card ${c.status}">
    <div class="eox-top">
      <div><div class="eox-pid">${rec.product_id}</div><div class="eox-name">${rec.product_name||''}</div></div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:0.3rem">${complianceBadge(c)}${daysNote(c)}</div>
    </div>
    <div class="eox-dates">
      <div><div class="date-label">End of Sale</div>${fmtDate(rec.end_of_sale)}</div>
      <div><div class="date-label">End of SW Maintenance</div>${fmtDate(rec.end_of_sw_maintenance)}</div>
      <div><div class="date-label">End of Security Support</div>${fmtDate(rec.end_of_security_support)}</div>
      <div><div class="date-label">End of Service Contract</div>${fmtDate(rec.end_of_service_contract)}</div>
      <div><div class="date-label">Last Date of Support</div>${fmtDate(rec.last_date_of_support)}</div>
    </div>
    ${rec.migration_product_id ? `<div class="migration-section"><div class="migration-label">Recommended Migration</div>
      <span class="migration-pid">${rec.migration_product_id}</span><span class="migration-info">${rec.migration_info||''}</span>
      ${rec.migration_url ? `<div class="migration-url"><a href="${rec.migration_url}" target="_blank">Product Info →</a></div>` : ''}</div>` : ''}
    ${rec.bulletin_url ? `<div class="bulletin-link" style="margin-top:0.6rem"><a href="${rec.bulletin_url}" target="_blank">EOL Bulletin →</a></div>` : ''}
  </div>`;
}
function renderSingleResults(results) {
  if (!results?.length) { resultsDiv.innerHTML = '<div class="no-results">No results.</div>'; return; }
  let html = '';
  for (const r of results) {
    const label = r.query_type === 'product_id' ? 'Product ID' : 'Serial Number';
    const pg = r.pagination;
    html += `<div class="result-section">
      <div class="result-header">
        <h3>${label}: <code style="color:#c9d1d9">${r.query}</code></h3>
        <span class="page-info">Page ${pg.page}/${pg.last_page} · ${pg.total_records} record(s)</span>
      </div>`;
    html += r.records.length ? r.records.map(renderRecord).join('') : '<div class="no-results">No records found.</div>';
    html += '</div>';
  }
  resultsDiv.innerHTML = html;
}

// ── Bulk Upload ──────────────────────────────────────────────────────────────
let bulkRows     = [];
let bulkHeaders  = [];
let eoxColNames  = [];
let currentPage  = 1;
const PAGE_SIZE  = 50;

const dropZone      = document.getElementById('dropZone');
const fileInput     = document.getElementById('fileInput');
const uploadBtn     = document.getElementById('uploadBtn');
const uploadStatus  = document.getElementById('uploadStatus');
const progressWrap  = document.getElementById('progressWrap');
const progressFill  = document.getElementById('progressFill');
const progressText  = document.getElementById('progressText');

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

function setFile(f) {
  dropZone.querySelector('p').textContent = `Selected: ${f.name} (${(f.size/1024).toFixed(0)} KB)`;
  uploadBtn.disabled = false;
  uploadStatus.textContent = '';
  document.getElementById('detectedCols').style.display = 'none';
}

document.getElementById('clearUploadBtn').addEventListener('click', () => {
  fileInput.value = '';
  dropZone.querySelector('p').textContent = 'Drag & drop your Excel file here, or click to browse';
  uploadBtn.disabled = true;
  uploadStatus.textContent = '';
  document.getElementById('detectedCols').style.display = 'none';
  document.getElementById('colMappingWrap').style.display = 'none';
  document.getElementById('bulkSummaryBar').style.display = 'none';
  document.getElementById('bulkChartWrap').style.display = 'none';
  document.getElementById('bulkDownloadBar').style.display = 'none';
  document.getElementById('bulkTableWrap').style.display = 'none';
  progressWrap.style.display = 'none';
  if (_chart) { _chart.destroy(); _chart = null; }
  bulkRows = []; bulkHeaders = []; eoxColNames = [];
});

function setProgress(pct, msg) {
  progressWrap.style.display = 'block';
  progressFill.style.width = pct + '%';
  progressText.textContent = msg;
}

uploadBtn.addEventListener('click', () => doUpload());

let _chart = null;

async function doUpload(extraFields = {}) {
  const f = fileInput.files[0];
  if (!f) return;
  uploadBtn.disabled = true;
  uploadStatus.textContent = '';
  document.getElementById('colMappingWrap').style.display = 'none';
  setProgress(10, 'Uploading file…');

  const fd = new FormData();
  fd.append('file', f);
  for (const [k, v] of Object.entries(extraFields)) fd.append(k, v);

  try {
    setProgress(30, 'Parsing file and querying EOX API…');
    const resp = await fetch('/upload', { method: 'POST', body: fd });
    const data = await resp.json();

    if (data.needs_mapping) {
      progressWrap.style.display = 'none';
      showColMapping(data.available_columns);
      return;
    }
    if (!resp.ok) {
      uploadStatus.textContent = 'Error: ' + (data.error || 'Unknown');
      progressWrap.style.display = 'none';
      return;
    }

    const lookupSummary = [
      data.stats.unique_pids ? `${data.stats.unique_pids} unique PIDs` : '',
      data.stats.unique_sns  ? `${data.stats.unique_sns} unique SNs`  : '',
    ].filter(Boolean).join(', ');
    setProgress(100, `Done — ${data.stats.total} rows processed (${lookupSummary})`);

    document.getElementById('colPid').textContent = data.pid_col ? `PID: "${data.pid_col}"` : 'PID: not found';
    document.getElementById('colSn').textContent  = data.sn_col  ? `SN: "${data.sn_col}"`   : 'SN: not found';
    document.getElementById('detectedCols').style.display = 'block';

    bulkRows    = data.rows;
    bulkHeaders = data.headers;
    eoxColNames = data.eox_col_names;
    currentPage = 1;

    renderSummary(data.stats);
    renderChart(data.stats);
    renderBulkTable();

    document.getElementById('downloadLink').href = `/download/${data.job_id}`;
    document.getElementById('bulkDownloadBar').style.display = 'block';

  } catch(err) {
    uploadStatus.textContent = 'Error: ' + err.message;
    progressWrap.style.display = 'none';
  } finally {
    uploadBtn.disabled = false;
  }
}

function showColMapping(cols) {
  const makeOpts = () => '<option value="">-- None --</option>' +
    cols.map(c => `<option value="${c.replace(/"/g,'&quot;')}">${c}</option>`).join('');
  document.getElementById('manualPidSel').innerHTML = makeOpts();
  document.getElementById('manualSnSel').innerHTML  = makeOpts();
  document.getElementById('colMappingWrap').style.display = 'block';
}

function resubmitWithMapping() {
  const pidCol = document.getElementById('manualPidSel').value;
  const snCol  = document.getElementById('manualSnSel').value;
  if (!pidCol && !snCol) { uploadStatus.textContent = 'Select at least one column.'; return; }
  const extra = {};
  if (pidCol) extra.pid_col = pidCol;
  if (snCol)  extra.sn_col  = snCol;
  doUpload(extra);
}

function renderChart(s) {
  document.getElementById('bulkChartWrap').style.display = 'block';
  const ctx = document.getElementById('complianceChart').getContext('2d');
  if (_chart) { _chart.destroy(); _chart = null; }
  _chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Compliant', 'Warning', 'Noncompliant', 'Unknown'],
      datasets: [{ data: [s.compliant, s.warning, s.noncompliant, s.unknown],
        backgroundColor: ['#3fb950', '#e3b341', '#f85149', '#6e7681'], borderWidth: 0 }]
    },
    options: {
      plugins: { legend: { labels: { color: '#8b949e', font: { size: 12 } } } },
      cutout: '65%',
    }
  });
}

function renderSummary(s) {
  const bar = document.getElementById('bulkSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Total Rows</span>
    <span class="pill pill-c">${s.compliant} Compliant</span>
    <span class="pill pill-w">${s.warning} Warning</span>
    <span class="pill pill-nc">${s.noncompliant} Noncompliant</span>
    ${s.unknown ? `<span class="pill pill-uk">${s.unknown} Unknown</span>` : ''}
    ${s.unique_pids ? `<span class="pill pill-uk">${s.unique_pids} Unique PIDs</span>` : ''}
    ${s.unique_sns  ? `<span class="pill pill-uk">${s.unique_sns} Unique SNs</span>`  : ''}`;
}

function complianceBadgeSm(label) {
  if (!label) return '<span class="badge-sm badge-sm-uk">Unknown</span>';
  const l = label.toLowerCase();
  if (l === 'noncompliant') return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  if (l.includes('warning')) return `<span class="badge-sm badge-sm-w">${label}</span>`;
  if (l === 'compliant')     return `<span class="badge-sm badge-sm-c">${label}</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function renderBulkTable() {
  const wrap = document.getElementById('bulkTableWrap');
  wrap.style.display = 'block';

  // Build header
  const thead = document.getElementById('bulkThead');
  const isEox = col => eoxColNames.includes(col);
  thead.innerHTML = '<tr>' + bulkHeaders.map(h =>
    `<th class="${isEox(h)?'eox-col':''}">${h}</th>`
  ).join('') + '</tr>';

  renderPage(currentPage);
}

function renderPage(page) {
  currentPage = page;
  const start = (page - 1) * PAGE_SIZE;
  const slice = bulkRows.slice(start, start + PAGE_SIZE);

  const tbody = document.getElementById('bulkTbody');
  const eoxDateCols = eoxColNames.filter(c => c !== 'EOX Compliance' && c !== 'EOX Migration PID');
  const complianceCol = 'EOX Compliance';

  tbody.innerHTML = slice.map(row => {
    return '<tr>' + bulkHeaders.map(h => {
      const v = row[h];
      if (h === complianceCol) return `<td>${complianceBadgeSm(v||'')}</td>`;
      if (eoxDateCols.includes(h)) {
        return `<td class="${!v?'na':'mono'}">${v||'N/A'}</td>`;
      }
      const display = (v === null || v === undefined || v === '') ? '' : String(v);
      return `<td title="${display.replace(/"/g,'&quot;')}">${display}</td>`;
    }).join('') + '</tr>';
  }).join('');

  renderPagination();
}

function renderPagination() {
  const total = bulkRows.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const pg = document.getElementById('pagination');
  if (pages <= 1) { pg.innerHTML = ''; return; }

  let html = `<span class="page-info-txt">Rows ${(currentPage-1)*PAGE_SIZE+1}–${Math.min(currentPage*PAGE_SIZE,total)} of ${total}</span>`;
  if (currentPage > 1)  html += `<button class="page-btn" onclick="renderPage(${currentPage-1})">‹ Prev</button>`;

  // Show up to 7 page buttons
  const start = Math.max(1, currentPage - 3);
  const end   = Math.min(pages, currentPage + 3);
  for (let i = start; i <= end; i++) {
    html += `<button class="page-btn${i===currentPage?' active':''}" onclick="renderPage(${i})">${i}</button>`;
  }
  if (currentPage < pages) html += `<button class="page-btn" onclick="renderPage(${currentPage+1})">Next ›</button>`;
  pg.innerHTML = html;
}

// ── Search history ────────────────────────────────────────────────────────────
const HISTORY_KEY = 'eox_search_history';
const MAX_HISTORY = 10;

function addToHistory(pid, sn) {
  if (!pid && !sn) return;
  let h = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  h = h.filter(e => !(e.pid === pid && e.sn === sn));
  h.unshift({ pid, sn });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(0, MAX_HISTORY)));
  renderHistory();
}

function renderHistory() {
  const h = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  const el = document.getElementById('searchHistory');
  if (!h.length) { el.innerHTML = ''; return; }
  el.innerHTML =
    '<span style="font-size:0.75rem;color:#6e7681;margin-right:0.4rem">Recent:</span>' +
    h.map((e, i) => {
      const label = [e.pid, e.sn].filter(Boolean).join(' / ');
      return `<button class="history-chip" onclick="applyHistory(${i})">${label}</button>`;
    }).join('');
}

function applyHistory(i) {
  const h = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  if (!h[i]) return;
  document.getElementById('pid').value = h[i].pid || '';
  document.getElementById('sn').value  = h[i].sn  || '';
  searchForm.dispatchEvent(new Event('submit'));
}

renderHistory();

// ── SWIM Single Search ────────────────────────────────────────────────────────
const swimSearchForm   = document.getElementById('swimSearchForm');
const swimResultsDiv   = document.getElementById('swimResults');
const swimSearchStatus = document.getElementById('swimSearchStatus');
const swimSearchBtn    = document.getElementById('swimSearchBtn');

document.getElementById('swimClearBtn').addEventListener('click', () => {
  document.getElementById('swimPid').value = '';
  swimResultsDiv.innerHTML = '';
  swimSearchStatus.textContent = '';
});

swimSearchForm.addEventListener('submit', async e => {
  e.preventDefault();
  const pid = document.getElementById('swimPid').value.trim();
  if (!pid) { swimSearchStatus.textContent = 'Enter a Product ID.'; return; }
  swimSearchBtn.disabled = true;
  swimSearchStatus.textContent = '';
  swimResultsDiv.innerHTML = '<div class="loading"><span class="spinner"></span>Querying SWIM API…</div>';
  try {
    const resp = await fetch('/swim/search', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pid}),
    });
    const data = await resp.json();
    if (!resp.ok) { swimResultsDiv.innerHTML = `<div class="error-msg">Error: ${data.error || 'Unknown'}</div>`; return; }
    renderSwimResults(data.result);
  } catch(err) {
    swimResultsDiv.innerHTML = `<div class="error-msg">Network error: ${err.message}</div>`;
  } finally { swimSearchBtn.disabled = false; }
});

function lifecycleBadge(lc) {
  const cl = (lc || '').toUpperCase();
  const css = cl === 'LONG_LIVED' ? 'badge-sm-c' : cl === 'CURRENT' ? 'badge-sm-c' : 'badge-sm-uk';
  return `<span class="badge-sm ${css}">${lc || 'N/A'}</span>`;
}

function renderSwimResults(result) {
  if (!result) { swimResultsDiv.innerHTML = '<div class="no-results">No result.</div>'; return; }
  if (result.error) { swimResultsDiv.innerHTML = `<div class="error-msg">${result.error}</div>`; return; }
  if (!result.products || !result.products.length) {
    swimResultsDiv.innerHTML = '<div class="no-results">No software suggestions found for this PID.</div>';
    return;
  }
  let html = '';
  for (const p of result.products) {
    html += `<div class="eox-card compliant">
      <div class="eox-top">
        <div><div class="eox-pid">${p.base_pid}</div><div class="eox-name">${p.product_name || ''}</div></div>
        <div style="font-size:0.8rem;color:#8b949e">${p.software_type || ''}</div>
      </div>`;
    for (const s of (p.suggestions || [])) {
      if (s.error) { html += `<div class="error-msg" style="margin-bottom:0.5rem">${s.error}</div>`; continue; }
      const sugBadge = s.is_suggested
        ? '<span class="badge-sm badge-sm-c" style="margin-left:0.5rem">★ Suggested</span>' : '';
      html += `<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:0.75rem;margin-bottom:0.6rem">
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
          <span class="eox-pid" style="font-size:0.95rem">${s.display_name}</span>
          ${lifecycleBadge(s.lifecycle)}${sugBadge}
        </div>
        <div class="eox-dates">
          <div><div class="date-label">Train</div><span class="date-value">${s.train_display || 'N/A'}</span></div>
          <div><div class="date-label">Release Date</div><span class="date-value">${s.release_date || 'N/A'}</span></div>
          <div><div class="date-label">Lifecycle</div><span class="date-value">${s.lifecycle || 'N/A'}</span></div>
        </div>`;
      if (s.images && s.images.length) {
        html += '<div style="margin-top:0.5rem"><div class="date-label" style="margin-bottom:0.35rem">Images</div>';
        for (const img of s.images) {
          const mb = img.size_bytes ? (parseInt(img.size_bytes)/1048576).toFixed(0)+' MB' : '';
          html += `<div style="font-family:monospace;font-size:0.78rem;color:#c9d1d9;margin-bottom:0.2rem">
            ${img.name}
            <span style="color:#6e7681;margin-left:0.5rem">${mb}</span>
            ${img.feature_set ? `<span style="color:#6e7681;margin-left:0.4rem">[${img.feature_set}]</span>` : ''}
          </div>`;
        }
        html += '</div>';
      }
      html += '</div>';
    }
    html += '</div>';
  }
  swimResultsDiv.innerHTML = html;
}

// ── SWIM Bulk Upload ──────────────────────────────────────────────────────────
let swimRows    = [];
let swimHeaders = [];
let swimEoxCols = [];
let swimPage    = 1;

const swimDropZone     = document.getElementById('swimDropZone');
const swimFileInput    = document.getElementById('swimFileInput');
const swimUploadBtn    = document.getElementById('swimUploadBtn');
const swimUploadStatus = document.getElementById('swimUploadStatus');
const swimProgressWrap = document.getElementById('swimProgressWrap');
const swimProgressFill = document.getElementById('swimProgressFill');
const swimProgressText = document.getElementById('swimProgressText');

swimDropZone.addEventListener('click', () => swimFileInput.click());
swimDropZone.addEventListener('dragover', e => { e.preventDefault(); swimDropZone.classList.add('dragover'); });
swimDropZone.addEventListener('dragleave', () => swimDropZone.classList.remove('dragover'));
swimDropZone.addEventListener('drop', e => {
  e.preventDefault(); swimDropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) setSwimFile(e.dataTransfer.files[0]);
});
swimFileInput.addEventListener('change', () => { if (swimFileInput.files[0]) setSwimFile(swimFileInput.files[0]); });

function setSwimFile(f) {
  swimDropZone.querySelector('p').textContent = `Selected: ${f.name} (${(f.size/1024).toFixed(0)} KB)`;
  swimUploadBtn.disabled = false;
  swimUploadStatus.textContent = '';
  document.getElementById('swimDetectedCols').style.display = 'none';
}

document.getElementById('swimClearUploadBtn').addEventListener('click', () => {
  swimFileInput.value = '';
  swimDropZone.querySelector('p').textContent = 'Drag & drop your Excel file here, or click to browse';
  swimUploadBtn.disabled = true;
  swimUploadStatus.textContent = '';
  document.getElementById('swimDetectedCols').style.display   = 'none';
  document.getElementById('swimColMappingWrap').style.display = 'none';
  document.getElementById('swimSummaryBar').style.display     = 'none';
  document.getElementById('swimDownloadBar').style.display    = 'none';
  document.getElementById('swimTableWrap').style.display      = 'none';
  swimProgressWrap.style.display = 'none';
  swimRows = []; swimHeaders = []; swimEoxCols = [];
});

function setSwimProgress(pct, msg) {
  swimProgressWrap.style.display = 'block';
  swimProgressFill.style.width = pct + '%';
  swimProgressText.textContent = msg;
}

swimUploadBtn.addEventListener('click', () => doSwimUpload());

async function doSwimUpload(extraFields = {}) {
  const f = swimFileInput.files[0];
  if (!f) return;
  swimUploadBtn.disabled = true;
  swimUploadStatus.textContent = '';
  document.getElementById('swimColMappingWrap').style.display = 'none';
  setSwimProgress(10, 'Uploading file…');

  const fd = new FormData();
  fd.append('file', f);
  for (const [k, v] of Object.entries(extraFields)) fd.append(k, v);

  try {
    setSwimProgress(30, 'Querying SWIM API (1 call per unique PID — may take a moment)…');
    const resp = await fetch('/swim/upload', { method: 'POST', body: fd });
    const data = await resp.json();

    if (data.needs_mapping && data.context === 'swim') {
      swimProgressWrap.style.display = 'none';
      const makeOpts = () => '<option value="">-- None --</option>' +
        data.available_columns.map(c => `<option value="${c.replace(/"/g,'&quot;')}">${c}</option>`).join('');
      document.getElementById('swimManualPidSel').innerHTML     = makeOpts();
      document.getElementById('swimManualVersionSel').innerHTML = makeOpts();
      document.getElementById('swimColMappingWrap').style.display = 'block';
      return;
    }
    if (!resp.ok) {
      swimUploadStatus.textContent = 'Error: ' + (data.error || 'Unknown');
      swimProgressWrap.style.display = 'none';
      return;
    }

    setSwimProgress(100, `Done — ${data.stats.total} rows processed (${data.stats.unique_pids} unique PIDs)`);

    document.getElementById('swimColPid').textContent     = data.pid_col     ? `PID: "${data.pid_col}"`         : 'PID: not found';
    document.getElementById('swimColVersion').textContent = data.version_col ? `Version: "${data.version_col}"` : 'Version: not detected';
    document.getElementById('swimDetectedCols').style.display = 'block';

    swimRows    = data.rows;
    swimHeaders = data.headers;
    swimEoxCols = data.swim_col_names;
    swimPage    = 1;

    renderSwimSummary(data.stats);
    renderSwimTable();

    document.getElementById('swimDownloadLink').href = `/swim/download/${data.job_id}`;
    document.getElementById('swimDownloadBar').style.display = 'block';

  } catch(err) {
    swimUploadStatus.textContent = 'Error: ' + err.message;
    swimProgressWrap.style.display = 'none';
  } finally {
    swimUploadBtn.disabled = false;
  }
}

function swimResubmitWithMapping() {
  const pidCol     = document.getElementById('swimManualPidSel').value;
  const versionCol = document.getElementById('swimManualVersionSel').value;
  if (!pidCol) { swimUploadStatus.textContent = 'Select at least the Product ID column.'; return; }
  const extra = { pid_col: pidCol };
  if (versionCol) extra.version_col = versionCol;
  doSwimUpload(extra);
}

function renderSwimSummary(s) {
  const bar = document.getElementById('swimSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Total Rows</span>
    <span class="pill pill-c">${s.compliant} Compliant</span>
    <span class="pill pill-nc">${s.non_compliant} Non-Compliant</span>
    <span class="pill pill-uk">${s.unknown} Unknown</span>
    <span class="pill pill-uk">${s.unique_pids} Unique PIDs</span>`;
}

function swimComplianceBadge(label) {
  if (!label) return '<span class="badge-sm badge-sm-uk">Unknown</span>';
  const l = label.toLowerCase();
  if (l === 'compliant')     return `<span class="badge-sm badge-sm-c">${label}</span>`;
  if (l === 'non-compliant') return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function renderSwimTable() {
  document.getElementById('swimTableWrap').style.display = 'block';
  const isSwim = col => swimEoxCols.includes(col);
  document.getElementById('swimThead').innerHTML =
    '<tr>' + swimHeaders.map(h => `<th class="${isSwim(h)?'eox-col':''}">${h}</th>`).join('') + '</tr>';
  renderSwimPage(swimPage);
}

function renderSwimPage(page) {
  swimPage = page;
  const start = (page - 1) * PAGE_SIZE;
  const slice = swimRows.slice(start, start + PAGE_SIZE);
  const compCol = 'SWIM Compliance';
  const dateCols = swimEoxCols.filter(c => c !== compCol);
  document.getElementById('swimTbody').innerHTML = slice.map(row =>
    '<tr>' + swimHeaders.map(h => {
      const v = row[h];
      if (h === compCol) return `<td>${swimComplianceBadge(v||'')}</td>`;
      if (dateCols.includes(h)) return `<td class="${!v?'na':'mono'}">${v||'N/A'}</td>`;
      const d = (v === null || v === undefined || v === '') ? '' : String(v);
      return `<td title="${d.replace(/"/g,'&quot;')}">${d}</td>`;
    }).join('') + '</tr>'
  ).join('');
  renderSwimPagination();
}

function renderSwimPagination() {
  const total = swimRows.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const pg = document.getElementById('swimPagination');
  if (pages <= 1) { pg.innerHTML = ''; return; }
  let html = `<span class="page-info-txt">Rows ${(swimPage-1)*PAGE_SIZE+1}–${Math.min(swimPage*PAGE_SIZE,total)} of ${total}</span>`;
  if (swimPage > 1) html += `<button class="page-btn" onclick="renderSwimPage(${swimPage-1})">‹ Prev</button>`;
  const s2 = Math.max(1, swimPage-3), e2 = Math.min(pages, swimPage+3);
  for (let i = s2; i <= e2; i++)
    html += `<button class="page-btn${i===swimPage?' active':''}" onclick="renderSwimPage(${i})">${i}</button>`;
  if (swimPage < pages) html += `<button class="page-btn" onclick="renderSwimPage(${swimPage+1})">Next ›</button>`;
  pg.innerHTML = html;
}

// ── PSIRT Single Search ───────────────────────────────────────────────────────
const psirtSearchForm   = document.getElementById('psirtSearchForm');
const psirtResultsDiv   = document.getElementById('psirtResults');
const psirtSearchStatus = document.getElementById('psirtSearchStatus');
const psirtSearchBtn    = document.getElementById('psirtSearchBtn');

document.getElementById('psirtClearBtn').addEventListener('click', () => {
  document.getElementById('psirtVersion').value = '';
  psirtResultsDiv.innerHTML = '';
  psirtSearchStatus.textContent = '';
});

psirtSearchForm.addEventListener('submit', async e => {
  e.preventDefault();
  const os_type = document.getElementById('psirtOsType').value;
  const version = document.getElementById('psirtVersion').value.trim();
  if (!version) { psirtSearchStatus.textContent = 'Enter a software version.'; return; }
  psirtSearchBtn.disabled = true;
  psirtSearchStatus.textContent = '';
  psirtResultsDiv.innerHTML = '<div class="loading"><span class="spinner"></span>Querying PSIRT API…</div>';
  try {
    const resp = await fetch('/psirt/search', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({os_type, version}),
    });
    const data = await resp.json();
    if (!resp.ok) { psirtResultsDiv.innerHTML = `<div class="error-msg">Error: ${data.error || 'Unknown'}</div>`; return; }
    renderPsirtResults(data.result);
  } catch(err) {
    psirtResultsDiv.innerHTML = `<div class="error-msg">Network error: ${err.message}</div>`;
  } finally { psirtSearchBtn.disabled = false; }
});

function psirtComplianceBadge(label) {
  if (!label) return '<span class="badge-sm badge-sm-uk">Unknown</span>';
  const l = label.toLowerCase();
  if (l === 'compliant')     return `<span class="badge-sm badge-sm-c">${label}</span>`;
  if (l === 'non-compliant') return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function psirtSirBadge(sir) {
  const l = (sir || '').toLowerCase();
  if (l === 'critical') return `<span class="badge-sm badge-sm-nc">${sir}</span>`;
  if (l === 'high')     return `<span class="badge-sm badge-sm-w">${sir}</span>`;
  return `<span class="badge-sm badge-sm-uk">${sir || 'N/A'}</span>`;
}

function renderPsirtResults(result) {
  if (!result) { psirtResultsDiv.innerHTML = '<div class="no-results">No result.</div>'; return; }
  if (result.error) { psirtResultsDiv.innerHTML = `<div class="error-msg">${result.error}</div>`; return; }

  const advs = result.advisories || [];
  const compClass = result.compliance === 'Non-Compliant' ? 'noncompliant'
                  : result.compliance === 'Compliant'     ? 'compliant' : 'unknown';

  const sirCounts = {};
  for (const a of advs) sirCounts[a.sir] = (sirCounts[a.sir] || 0) + 1;
  const sirSummary = Object.entries(sirCounts)
    .sort(([a],[b]) => (['Critical','High','Medium','Low'].indexOf(a)) - (['Critical','High','Medium','Low'].indexOf(b)))
    .map(([s,n]) => `${psirtSirBadge(s)} <span style="font-size:0.8rem;color:#8b949e">&times;${n}</span>`)
    .join(' &nbsp; ');

  let html = `<div class="eox-card ${compClass}">
    <div class="eox-top">
      <div>
        <div class="eox-pid">${result.os_type.toUpperCase()} ${result.version}</div>
        <div class="eox-name">${advs.length} advisory${advs.length!==1?'s':''} found</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:0.4rem">
        ${psirtComplianceBadge(result.compliance)}
        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;justify-content:flex-end">${sirSummary}</div>
      </div>
    </div>`;

  if (advs.length) {
    html += `<div style="overflow-x:auto;margin-top:0.75rem"><table style="width:100%;border-collapse:collapse;font-size:0.78rem">
      <thead><tr>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap">SIR</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Title</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap">Advisory ID</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap">CVSS</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">CVEs</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap">Published</th>
      </tr></thead><tbody>`;
    for (const a of advs) {
      const cves = (a.cves || []).join(', ') || 'N/A';
      const url  = a.publication_url
        ? `<a href="${a.publication_url}" target="_blank" style="color:#58a6ff;font-family:monospace;font-size:0.78rem">${a.advisory_id}</a>`
        : `<span style="font-family:monospace">${a.advisory_id}</span>`;
      html += `<tr style="border-bottom:1px solid #21262d">
        <td style="padding:0.4rem 0.6rem">${psirtSirBadge(a.sir)}</td>
        <td style="padding:0.4rem 0.6rem;color:#c9d1d9;max-width:320px;overflow:hidden;text-overflow:ellipsis" title="${a.title.replace(/"/g,'&quot;')}">${a.title}</td>
        <td style="padding:0.4rem 0.6rem;white-space:nowrap">${url}</td>
        <td style="padding:0.4rem 0.6rem;color:#8b949e;font-family:monospace">${a.cvss_score || 'N/A'}</td>
        <td style="padding:0.4rem 0.6rem;color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${cves}">${cves}</td>
        <td style="padding:0.4rem 0.6rem;color:#8b949e;white-space:nowrap;font-family:monospace">${(a.first_published||'').slice(0,10)||'N/A'}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }
  html += '</div>';
  psirtResultsDiv.innerHTML = html;
}

// ── PSIRT Bulk Upload ─────────────────────────────────────────────────────────
let psirtRows    = [];
let psirtHeaders = [];
let psirtCols    = [];
let psirtPage    = 1;

const psirtDropZone     = document.getElementById('psirtDropZone');
const psirtFileInput    = document.getElementById('psirtFileInput');
const psirtUploadBtn    = document.getElementById('psirtUploadBtn');
const psirtUploadStatus = document.getElementById('psirtUploadStatus');
const psirtProgressWrap = document.getElementById('psirtProgressWrap');
const psirtProgressFill = document.getElementById('psirtProgressFill');
const psirtProgressText = document.getElementById('psirtProgressText');

psirtDropZone.addEventListener('click', () => psirtFileInput.click());
psirtDropZone.addEventListener('dragover', e => { e.preventDefault(); psirtDropZone.classList.add('dragover'); });
psirtDropZone.addEventListener('dragleave', () => psirtDropZone.classList.remove('dragover'));
psirtDropZone.addEventListener('drop', e => {
  e.preventDefault(); psirtDropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) setPsirtFile(e.dataTransfer.files[0]);
});
psirtFileInput.addEventListener('change', () => { if (psirtFileInput.files[0]) setPsirtFile(psirtFileInput.files[0]); });

function setPsirtFile(f) {
  psirtDropZone.querySelector('p').textContent = `Selected: ${f.name} (${(f.size/1024).toFixed(0)} KB)`;
  psirtUploadBtn.disabled = false;
  psirtUploadStatus.textContent = '';
  document.getElementById('psirtDetectedCols').style.display = 'none';
}

document.getElementById('psirtClearUploadBtn').addEventListener('click', () => {
  psirtFileInput.value = '';
  psirtDropZone.querySelector('p').textContent = 'Drag & drop your Excel file here, or click to browse';
  psirtUploadBtn.disabled = true;
  psirtUploadStatus.textContent = '';
  document.getElementById('psirtDetectedCols').style.display    = 'none';
  document.getElementById('psirtColMappingWrap').style.display  = 'none';
  document.getElementById('psirtSummaryBar').style.display      = 'none';
  document.getElementById('psirtDownloadBar').style.display     = 'none';
  document.getElementById('psirtTableWrap').style.display       = 'none';
  psirtProgressWrap.style.display = 'none';
  psirtRows = []; psirtHeaders = []; psirtCols = [];
});

function setPsirtProgress(pct, msg) {
  psirtProgressWrap.style.display = 'block';
  psirtProgressFill.style.width = pct + '%';
  psirtProgressText.textContent = msg;
}

psirtUploadBtn.addEventListener('click', () => doPsirtUpload());

async function doPsirtUpload(extraFields = {}) {
  const f = psirtFileInput.files[0];
  if (!f) return;
  psirtUploadBtn.disabled = true;
  psirtUploadStatus.textContent = '';
  document.getElementById('psirtColMappingWrap').style.display = 'none';
  setPsirtProgress(10, 'Uploading file…');

  const fd = new FormData();
  fd.append('file', f);
  for (const [k, v] of Object.entries(extraFields)) fd.append(k, v);

  try {
    setPsirtProgress(30, 'Querying PSIRT API (1 call per unique version — may take a moment)…');
    const resp = await fetch('/psirt/upload', { method: 'POST', body: fd });
    const data = await resp.json();

    if (data.needs_mapping && data.context === 'psirt') {
      psirtProgressWrap.style.display = 'none';
      const makeOpts = () => '<option value="">-- None --</option>' +
        data.available_columns.map(c => `<option value="${c.replace(/"/g,'&quot;')}">${c}</option>`).join('');
      document.getElementById('psirtManualVersionSel').innerHTML = makeOpts();
      document.getElementById('psirtManualOsTypeSel').innerHTML  = makeOpts();
      document.getElementById('psirtColMappingWrap').style.display = 'block';
      return;
    }
    if (!resp.ok) {
      psirtUploadStatus.textContent = 'Error: ' + (data.error || 'Unknown');
      psirtProgressWrap.style.display = 'none';
      return;
    }

    setPsirtProgress(100, `Done — ${data.stats.total} rows processed (${data.stats.unique_versions} unique versions)`);

    document.getElementById('psirtColVersion').textContent = data.version_col ? `Version: "${data.version_col}"` : 'Version: not found';
    document.getElementById('psirtColOsType').textContent  = data.os_type_col ? `OS Type: "${data.os_type_col}"` : `OS Type: default (${data.default_os_type})`;
    document.getElementById('psirtDetectedCols').style.display = 'block';

    psirtRows    = data.rows;
    psirtHeaders = data.headers;
    psirtCols    = data.psirt_col_names;
    psirtPage    = 1;

    renderPsirtSummary(data.stats);
    renderPsirtTable();

    document.getElementById('psirtDownloadLink').href = `/psirt/download/${data.job_id}`;
    document.getElementById('psirtDownloadBar').style.display = 'block';

  } catch(err) {
    psirtUploadStatus.textContent = 'Error: ' + err.message;
    psirtProgressWrap.style.display = 'none';
  } finally {
    psirtUploadBtn.disabled = false;
  }
}

function psirtResubmitWithMapping() {
  const versionCol    = document.getElementById('psirtManualVersionSel').value;
  const osTypeCol     = document.getElementById('psirtManualOsTypeSel').value;
  const defaultOsType = document.getElementById('psirtDefaultOsTypeSel').value;
  if (!versionCol) { psirtUploadStatus.textContent = 'Select the software version column.'; return; }
  const extra = { version_col: versionCol, default_os_type: defaultOsType };
  if (osTypeCol) extra.os_type_col = osTypeCol;
  doPsirtUpload(extra);
}

function renderPsirtSummary(s) {
  const bar = document.getElementById('psirtSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Total Rows</span>
    <span class="pill pill-c">${s.compliant} Compliant</span>
    <span class="pill pill-nc">${s.non_compliant} Non-Compliant</span>
    <span class="pill pill-uk">${s.na} NA</span>
    <span class="pill pill-uk">${s.unique_versions} Unique Versions</span>`;
}

function renderPsirtTable() {
  document.getElementById('psirtTableWrap').style.display = 'block';
  const isPsirt = col => psirtCols.includes(col);
  document.getElementById('psirtThead').innerHTML =
    '<tr>' + psirtHeaders.map(h => `<th class="${isPsirt(h)?'eox-col':''}">${h}</th>`).join('') + '</tr>';
  renderPsirtPage(psirtPage);
}

function renderPsirtPage(page) {
  psirtPage = page;
  const start = (page - 1) * PAGE_SIZE;
  const slice = psirtRows.slice(start, start + PAGE_SIZE);
  const compCol = 'PSIRT Compliance';
  document.getElementById('psirtTbody').innerHTML = slice.map(row =>
    '<tr>' + psirtHeaders.map(h => {
      const v = row[h];
      if (h === compCol) return `<td>${psirtComplianceBadge(v||'')}</td>`;
      if (psirtCols.includes(h) && h !== compCol) {
        const d = (v === null || v === undefined || v === '') ? '' : String(v);
        return `<td class="${!d?'na':'mono'}" title="${d.replace(/"/g,'&quot;')}">${d||'N/A'}</td>`;
      }
      const d = (v === null || v === undefined || v === '') ? '' : String(v);
      return `<td title="${d.replace(/"/g,'&quot;')}">${d}</td>`;
    }).join('') + '</tr>'
  ).join('');
  renderPsirtPagination();
}

function renderPsirtPagination() {
  const total = psirtRows.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const pg = document.getElementById('psirtPagination');
  if (pages <= 1) { pg.innerHTML = ''; return; }
  let html = `<span class="page-info-txt">Rows ${(psirtPage-1)*PAGE_SIZE+1}–${Math.min(psirtPage*PAGE_SIZE,total)} of ${total}</span>`;
  if (psirtPage > 1) html += `<button class="page-btn" onclick="renderPsirtPage(${psirtPage-1})">‹ Prev</button>`;
  const ps = Math.max(1, psirtPage-3), pe = Math.min(pages, psirtPage+3);
  for (let i = ps; i <= pe; i++)
    html += `<button class="page-btn${i===psirtPage?' active':''}" onclick="renderPsirtPage(${i})">${i}</button>`;
  if (psirtPage < pages) html += `<button class="page-btn" onclick="renderPsirtPage(${psirtPage+1})">Next ›</button>`;
  pg.innerHTML = html;
}
</script>
</body>
</html>
"""


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/search", methods=["POST"])
def search():
    data = request.get_json(force=True)
    pid = (data.get("pid") or "").strip()
    sn  = (data.get("sn")  or "").strip()
    if not pid and not sn:
        return jsonify({"error": "Provide a Product ID or Serial Number"}), 400
    results = []
    try:
        if pid:
            if "*" in pid:
                results.append(cisco_eox.query_all_pages_by_product_id(pid))
            else:
                results.append(cisco_eox.query_by_product_id(pid))
        if sn:  results.append(cisco_eox.query_by_serial_number(sn))
    except ValueError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": f"API error: {e}"}), 502
    return jsonify({"results": results})


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Read file (Excel or CSV)
    fname = f.filename.lower()
    try:
        if fname.endswith(".csv"):
            df = pd.read_csv(f, dtype=str)
        else:
            df = pd.read_excel(f, dtype=str)
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400

    df = df.fillna("")

    # Honour manual column overrides from the column-mapping UI
    pid_col = request.form.get("pid_col", "").strip() or _find_col(df, PID_KEYWORDS)
    sn_col  = request.form.get("sn_col",  "").strip() or _find_col(df, SN_KEYWORDS)

    if not pid_col and not sn_col:
        return jsonify({"needs_mapping": True, "available_columns": list(df.columns)})

    # Build EOX lookup from unique PIDs and/or SNs
    pid_lookup: dict = {}
    sn_lookup: dict = {}
    unique_pids: list = []
    unique_sns: list = []
    try:
        if pid_col:
            unique_pids = [str(v).strip() for v in df[pid_col].unique() if str(v).strip()]
            pid_lookup = _build_pid_lookup(unique_pids)
        if sn_col:
            unique_sns = [str(v).strip() for v in df[sn_col].unique() if str(v).strip()]
            sn_lookup = _build_sn_lookup(unique_sns)
    except Exception as e:
        return jsonify({"error": f"EOX API error: {e}"}), 502

    # Add EOX columns to DataFrame
    eox_col_names = [c[0] for c in EOX_COLS]
    for col_name in eox_col_names:
        df[col_name] = ""

    for idx, row in df.iterrows():
        rec = None
        if pid_col:
            rec = pid_lookup.get(str(row[pid_col]).strip().upper())
        if rec is None and sn_col:
            rec = sn_lookup.get(str(row[sn_col]).strip().upper())

        if rec:
            df.at[idx, "EOX End of Sale"]             = rec.get("end_of_sale", "")
            df.at[idx, "EOX End of SW Maintenance"]   = rec.get("end_of_sw_maintenance", "")
            df.at[idx, "EOX End of Security Support"] = rec.get("end_of_security_support", "")
            df.at[idx, "EOX End of Service Contract"] = rec.get("end_of_service_contract", "")
            df.at[idx, "EOX Last Date of Support"]    = rec.get("last_date_of_support", "")
            df.at[idx, "EOX Compliance"]              = rec.get("compliance", {}).get("label", "")
            df.at[idx, "EOX Migration PID"]           = rec.get("migration_product_id", "")

    # Stats
    compliance_col = df["EOX Compliance"]
    stats = {
        "total":        len(df),
        "unique_pids":  len(unique_pids),
        "unique_sns":   len(unique_sns),
        "compliant":    int((compliance_col == "Compliant").sum()),
        "warning":      int((compliance_col == "Compliant with Warning").sum()),
        "noncompliant": int((compliance_col == "Noncompliant").sum()),
        "unknown":      int((compliance_col == "").sum()),
    }

    # Persist enriched df for download
    job_id = str(uuid.uuid4())[:8]
    _store_job(job_id, df)

    # Return rows as list of dicts
    rows = df.to_dict(orient="records")
    headers = list(df.columns)

    return jsonify({
        "job_id":       job_id,
        "pid_col":      pid_col,
        "sn_col":       sn_col,
        "headers":      headers,
        "eox_col_names": eox_col_names,
        "rows":         rows,
        "stats":        stats,
    })


@app.route("/download/<job_id>")
def download(job_id):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    buf = io.BytesIO()
    df.to_excel(buf, index=False, engine="openpyxl")
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        download_name="cisco_eox_enriched.xlsx",
        as_attachment=True,
    )


@app.route("/swim/search", methods=["POST"])
def swim_search():
    data = request.get_json(force=True)
    pid = (data.get("pid") or "").strip()
    if not pid:
        return jsonify({"error": "Provide a Product ID"}), 400
    if "*" in pid or "," in pid:
        return jsonify({"error": "SWIM requires a single exact PID — wildcards and comma-separated lists are not supported"}), 400
    try:
        result = cisco_swim.query_all_pages_swim_by_pid(pid)
    except ValueError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": f"API error: {e}"}), 502
    return jsonify({"result": result})


@app.route("/swim/upload", methods=["POST"])
def swim_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    fname = f.filename.lower()
    try:
        df = pd.read_csv(f, dtype=str) if fname.endswith(".csv") else pd.read_excel(f, dtype=str)
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400
    df = df.fillna("")

    pid_col     = request.form.get("pid_col", "").strip()     or _find_col(df, PID_KEYWORDS)
    version_col = request.form.get("version_col", "").strip() or _find_col(df, SWIM_VERSION_KEYWORDS)

    if not pid_col:
        return jsonify({"needs_mapping": True, "available_columns": list(df.columns), "context": "swim"})

    unique_pids = [str(v).strip() for v in df[pid_col].unique() if str(v).strip()]
    try:
        swim_lookup = _build_swim_lookup(unique_pids)
    except Exception as e:
        return jsonify({"error": f"SWIM API error: {e}"}), 502

    swim_col_names = [c[0] for c in SWIM_COLS]
    for col_name in swim_col_names:
        df[col_name] = ""

    for idx, row in df.iterrows():
        pid_val = str(row[pid_col]).strip().upper()
        rec = swim_lookup.get(pid_val) or {}
        suggested = rec.get("suggested_release", "")
        lifecycle  = rec.get("lifecycle", "")
        df.at[idx, "SWIM Suggested Release"] = suggested
        df.at[idx, "SWIM Lifecycle"]         = lifecycle
        if version_col:
            df.at[idx, "SWIM Compliance"] = cisco_swim._swim_compliance(
                str(row[version_col]), suggested
            )

    compliance_col = df["SWIM Compliance"]
    stats = {
        "total":        len(df),
        "unique_pids":  len(unique_pids),
        "compliant":    int((compliance_col == "Compliant").sum()),
        "non_compliant":int((compliance_col == "Non-Compliant").sum()),
        "unknown":      int(((compliance_col == "") | (compliance_col == "Unknown")).sum()),
    }

    job_id = str(uuid.uuid4())[:8]
    _store_job(job_id, df)

    return jsonify({
        "job_id":          job_id,
        "pid_col":         pid_col,
        "version_col":     version_col,
        "headers":         list(df.columns),
        "swim_col_names":  swim_col_names,
        "rows":            df.to_dict(orient="records"),
        "stats":           stats,
    })


@app.route("/swim/download/<job_id>")
def swim_download(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    buf = io.BytesIO()
    df.to_excel(buf, index=False, engine="openpyxl")
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        download_name="cisco_swim_enriched.xlsx",
        as_attachment=True,
    )


@app.route("/psirt/search", methods=["POST"])
def psirt_search():
    data = request.get_json(force=True)
    os_type = (data.get("os_type") or "").strip().lower()
    version = (data.get("version") or "").strip()
    if not os_type or not version:
        return jsonify({"error": "Provide os_type and version"}), 400
    if os_type not in cisco_psirt.OS_TYPES:
        return jsonify({"error": f"Unknown OS type '{os_type}'. Valid: {', '.join(cisco_psirt.OS_TYPES)}"}), 400
    try:
        result = cisco_psirt.query_psirt_by_version(os_type, version)
    except Exception as e:
        return jsonify({"error": f"API error: {e}"}), 502
    return jsonify({"result": result})


@app.route("/psirt/upload", methods=["POST"])
def psirt_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    fname = f.filename.lower()
    try:
        df = pd.read_csv(f, dtype=str) if fname.endswith(".csv") else pd.read_excel(f, dtype=str)
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400
    df = df.fillna("")

    version_col     = request.form.get("version_col", "").strip()     or _find_col(df, SWIM_VERSION_KEYWORDS)
    os_type_col     = request.form.get("os_type_col", "").strip()     or _find_col(df, OS_TYPE_KEYWORDS)
    default_os_type = request.form.get("default_os_type", "iosxe").strip().lower()

    if not version_col:
        return jsonify({"needs_mapping": True, "available_columns": list(df.columns), "context": "psirt"})

    # Build unique (os_type, version) pairs
    pairs: list[tuple[str, str]] = []
    for _, row in df.iterrows():
        ver = str(row[version_col]).strip()
        if not ver:
            continue
        ost = str(row[os_type_col]).strip().lower() if os_type_col else default_os_type
        if not ost or ost not in cisco_psirt.OS_TYPES:
            ost = default_os_type
        pairs.append((ost, ver))

    unique_pairs = list(dict.fromkeys(pairs))  # deduplicate preserving order
    try:
        psirt_lookup = _build_psirt_lookup(unique_pairs)
    except Exception as e:
        return jsonify({"error": f"PSIRT API error: {e}"}), 502

    psirt_col_names = [c[0] for c in PSIRT_COLS]
    for col_name in psirt_col_names:
        df[col_name] = ""

    for idx, row in df.iterrows():
        ver = str(row[version_col]).strip()
        if not ver:
            df.at[idx, "PSIRT Compliance"] = "NA"
            continue
        ost = str(row[os_type_col]).strip().lower() if os_type_col else default_os_type
        if not ost or ost not in cisco_psirt.OS_TYPES:
            ost = default_os_type
        rec = psirt_lookup.get((ost, ver.lower())) or {}
        df.at[idx, "PSIRT Compliance"]          = rec.get("compliance", "")
        df.at[idx, "PSIRT Critical Advisories"]  = str(rec.get("critical_count", "")) if rec else ""
        df.at[idx, "PSIRT Advisory IDs"]         = rec.get("advisory_ids", "")
        df.at[idx, "PSIRT CVEs"]                 = rec.get("cves", "")

    comp_col = df["PSIRT Compliance"]
    stats = {
        "total":           len(df),
        "unique_versions": len(unique_pairs),
        "compliant":       int((comp_col == "Compliant").sum()),
        "non_compliant":   int((comp_col == "Non-Compliant").sum()),
        "na":              int(((comp_col == "NA") | (comp_col == "")).sum()),
    }

    job_id = str(uuid.uuid4())[:8]
    _store_job(job_id, df)

    return jsonify({
        "job_id":          job_id,
        "version_col":     version_col,
        "os_type_col":     os_type_col,
        "default_os_type": default_os_type,
        "headers":         list(df.columns),
        "psirt_col_names": psirt_col_names,
        "rows":            df.to_dict(orient="records"),
        "stats":           stats,
    })


@app.route("/psirt/download/<job_id>")
def psirt_download(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    buf = io.BytesIO()
    df.to_excel(buf, index=False, engine="openpyxl")
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        download_name="cisco_psirt_enriched.xlsx",
        as_attachment=True,
    )


if __name__ == "__main__":
    print("Cisco EOX Finder running at http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
