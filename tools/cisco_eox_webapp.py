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
import sys
import uuid
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, render_template_string, request, send_file

sys.path.insert(0, str(Path(__file__).parent))
import cisco_eox

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# In-memory job store: job_id -> enriched DataFrame
_jobs: dict = {}

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

# ── Batched PID lookup ───────────────────────────────────────────────────────
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
</style>
</head>
<body>

<header>
  <div class="logo">Cisco <span>EOX</span> Finder</div>
  <p>End-of-Life compliance checker — EOX V5 API</p>
</header>

<div class="tabs">
  <button class="tab-btn active" data-tab="single">Single Search</button>
  <button class="tab-btn" data-tab="bulk">Bulk Excel Upload</button>
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
      <p style="font-size:0.75rem;color:#6e7681">.xlsx files · auto-detects "Product Part" and "Serial Number" columns</p>
      <input type="file" id="fileInput" accept=".xlsx,.xls" style="display:none">
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

    <div class="btn-row">
      <button id="uploadBtn" class="btn-primary" disabled>Process File</button>
      <button id="clearUploadBtn" class="btn-secondary">Clear</button>
      <span id="uploadStatus" class="status-msg"></span>
    </div>
  </div>

  <!-- Summary + Download -->
  <div id="bulkSummaryBar" class="summary-bar" style="display:none"></div>

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
  document.getElementById('bulkSummaryBar').style.display = 'none';
  document.getElementById('bulkDownloadBar').style.display = 'none';
  document.getElementById('bulkTableWrap').style.display = 'none';
  progressWrap.style.display = 'none';
  bulkRows = []; bulkHeaders = []; eoxColNames = [];
});

function setProgress(pct, msg) {
  progressWrap.style.display = 'block';
  progressFill.style.width = pct + '%';
  progressText.textContent = msg;
}

uploadBtn.addEventListener('click', async () => {
  const f = fileInput.files[0];
  if (!f) return;
  uploadBtn.disabled = true;
  uploadStatus.textContent = '';
  setProgress(10, 'Uploading file…');

  const fd = new FormData();
  fd.append('file', f);

  try {
    setProgress(30, 'Parsing Excel and querying EOX API…');
    const resp = await fetch('/upload', { method: 'POST', body: fd });
    const data = await resp.json();
    if (!resp.ok) { uploadStatus.textContent = 'Error: ' + (data.error || 'Unknown'); progressWrap.style.display='none'; return; }

    setProgress(100, `Done — ${data.stats.total} rows processed (${data.stats.unique_pids} unique PIDs)`);

    // Show detected columns
    document.getElementById('colPid').textContent = data.pid_col ? `PID: "${data.pid_col}"` : 'PID: not found';
    document.getElementById('colSn').textContent  = data.sn_col  ? `SN: "${data.sn_col}"`   : 'SN: not found';
    document.getElementById('detectedCols').style.display = 'block';

    bulkRows    = data.rows;
    bulkHeaders = data.headers;
    eoxColNames = data.eox_col_names;
    currentPage = 1;

    renderSummary(data.stats);
    renderBulkTable();

    document.getElementById('downloadLink').href = `/download/${data.job_id}`;
    document.getElementById('bulkDownloadBar').style.display = 'block';

  } catch(err) {
    uploadStatus.textContent = 'Error: ' + err.message;
    progressWrap.style.display = 'none';
  } finally {
    uploadBtn.disabled = false;
  }
});

function renderSummary(s) {
  const bar = document.getElementById('bulkSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Total Rows</span>
    <span class="pill pill-c">${s.compliant} Compliant</span>
    <span class="pill pill-w">${s.warning} Warning</span>
    <span class="pill pill-nc">${s.noncompliant} Noncompliant</span>
    ${s.unknown ? `<span class="pill pill-uk">${s.unknown} Unknown</span>` : ''}
    <span class="pill pill-uk">${s.unique_pids} Unique PIDs</span>`;
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
</script>
</body>
</html>
"""


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
        if pid: results.append(cisco_eox.query_by_product_id(pid))
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

    # Read Excel
    try:
        df = pd.read_excel(f, dtype=str)
    except Exception as e:
        return jsonify({"error": f"Could not read Excel: {e}"}), 400

    df = df.fillna("")

    # Detect columns
    pid_col = _find_col(df, PID_KEYWORDS)
    sn_col  = _find_col(df, SN_KEYWORDS)

    if not pid_col and not sn_col:
        return jsonify({"error": "Could not find 'Product Part' or 'Serial Number' column. "
                                 "Please ensure your Excel has these column headers."}), 400

    # Build EOX lookup from unique PIDs
    pid_lookup: dict = {}
    unique_pids: list = []
    if pid_col:
        unique_pids = [str(v).strip() for v in df[pid_col].unique() if str(v).strip()]
        try:
            pid_lookup = _build_pid_lookup(unique_pids)
        except Exception as e:
            return jsonify({"error": f"EOX API error: {e}"}), 502

    # Add EOX columns to DataFrame
    eox_col_names = [c[0] for c in EOX_COLS]
    for col_name in eox_col_names:
        df[col_name] = ""

    for idx, row in df.iterrows():
        rec = None
        if pid_col:
            pid_val = str(row[pid_col]).strip().upper()
            rec = pid_lookup.get(pid_val)

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
        "total":       len(df),
        "unique_pids": len(unique_pids),
        "compliant":   int((compliance_col == "Compliant").sum()),
        "warning":     int((compliance_col == "Compliant with Warning").sum()),
        "noncompliant":int((compliance_col == "Noncompliant").sum()),
        "unknown":     int((compliance_col == "").sum()),
    }

    # Store enriched df for download
    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = df

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
    df = _jobs.get(job_id)
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


if __name__ == "__main__":
    print("Cisco EOX Finder running at http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
