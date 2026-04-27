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
import os
import pickle
import smtplib
import sqlite3
import sys
import time
import uuid
import zipfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, render_template_string, request, send_file

sys.path.insert(0, str(Path(__file__).parent))
import cisco_eox
import cisco_bug
import cisco_config_diff
import cisco_psirt
import cisco_sn2info
import cisco_swim

try:
    import anthropic as _anthropic_lib
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

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
    conn.execute(
        "CREATE TABLE IF NOT EXISTS saved_lists "
        "(list_id TEXT PRIMARY KEY, name TEXT NOT NULL, "
        "columns_json TEXT NOT NULL, rows_json TEXT NOT NULL, created_at INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS job_meta "
        "(job_id TEXT PRIMARY KEY, job_type TEXT NOT NULL, "
        "stats_json TEXT NOT NULL, created_at INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS config_baselines "
        "(baseline_id TEXT PRIMARY KEY, name TEXT NOT NULL, "
        "content TEXT NOT NULL, created_at INTEGER NOT NULL)"
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

# ── Job metadata (for dashboard) ─────────────────────────────────────────────
def _record_job_meta(job_id: str, job_type: str, stats: dict) -> None:
    import json as _json
    with _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO job_meta (job_id, job_type, stats_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (job_id, job_type, _json.dumps(stats), int(time.time())),
        )
        conn.execute("DELETE FROM job_meta WHERE created_at < ?", (int(time.time()) - 90 * 86400,))

# ── Saved device lists ───────────────────────────────────────────────────────
def _list_saved_lists() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT list_id, name, columns_json, rows_json, created_at "
            "FROM saved_lists ORDER BY created_at DESC"
        ).fetchall()
    import json as _json
    return [
        {"list_id": r[0], "name": r[1],
         "columns": _json.loads(r[2]), "rows": _json.loads(r[3]),
         "created_at": r[4]}
        for r in rows
    ]


def _save_list(name: str, columns: list, rows: list) -> str:
    import json as _json
    list_id = str(uuid.uuid4())[:8]
    with _db() as conn:
        conn.execute(
            "INSERT INTO saved_lists (list_id, name, columns_json, rows_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (list_id, name, _json.dumps(columns), _json.dumps(rows), int(time.time())),
        )
    return list_id


def _delete_saved_list(list_id: str) -> bool:
    with _db() as conn:
        cur = conn.execute("DELETE FROM saved_lists WHERE list_id = ?", (list_id,))
    return cur.rowcount > 0

# ── Config baselines ─────────────────────────────────────────────────────────
def _list_baselines() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT baseline_id, name, created_at FROM config_baselines ORDER BY created_at DESC"
        ).fetchall()
    return [{"baseline_id": r[0], "name": r[1], "created_at": r[2]} for r in rows]


def _save_baseline(name: str, content: str) -> str:
    bid = str(uuid.uuid4())[:8]
    with _db() as conn:
        conn.execute(
            "INSERT INTO config_baselines (baseline_id, name, content, created_at) VALUES (?, ?, ?, ?)",
            (bid, name, content, int(time.time())),
        )
    return bid


def _load_baseline(bid: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT baseline_id, name, content, created_at FROM config_baselines WHERE baseline_id = ?",
            (bid,),
        ).fetchone()
    return {"baseline_id": row[0], "name": row[1], "content": row[2], "created_at": row[3]} if row else None


def _delete_baseline(bid: str) -> bool:
    with _db() as conn:
        cur = conn.execute("DELETE FROM config_baselines WHERE baseline_id = ?", (bid,))
    return cur.rowcount > 0


# ── Webhook alerts ───────────────────────────────────────────────────────────
_WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")


def _send_webhook_alert(job_type: str, stats: dict, job_id: str) -> None:
    """POST a Slack/Teams-compatible alert when non-compliant devices are found."""
    if not _WEBHOOK_URL:
        return
    non_compliant = (
        stats.get("non_compliant") or stats.get("noncompliant")
        or stats.get("psirt_non_compliant") or stats.get("bug_non_compliant") or 0
    )
    if not non_compliant:
        return
    try:
        import requests as _req
        total = stats.get("total", 0)
        label = job_type.upper()
        text = (
            f":rotating_light: *{label} Alert* — {non_compliant} of {total} rows "
            f"are Non-Compliant (Job `{job_id}`)"
        )
        # Slack uses {"text":...}; Teams uses {"text":...} too via Incoming Webhook
        _req.post(_WEBHOOK_URL, json={"text": text}, timeout=5)
    except Exception as exc:
        print(f"Webhook send failed: {exc}", file=sys.stderr)

# ── Email alerts (SMTP) ──────────────────────────────────────────────────────
_SMTP_HOST     = os.getenv("SMTP_HOST", "")
_SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
_SMTP_USER     = os.getenv("SMTP_USER", "")
_SMTP_PASS     = os.getenv("SMTP_PASS", "")
_ALERT_FROM    = os.getenv("ALERT_EMAIL_FROM", _SMTP_USER)
_ALERT_TO      = os.getenv("ALERT_EMAIL_TO", "")   # comma-separated
_ALERT_MIN_NC  = int(os.getenv("ALERT_MIN_NONCOMPLIANT", "1"))  # min non-compliant to trigger


def _smtp_configured() -> bool:
    return bool(_SMTP_HOST and _ALERT_TO)


_ANTHROPIC_CLIENT = None


def _get_anthropic_client():
    """Lazy-init Anthropic client. Raises RuntimeError if unavailable."""
    global _ANTHROPIC_CLIENT
    if not _ANTHROPIC_AVAILABLE:
        raise RuntimeError("anthropic package not installed")
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY env var not set")
    if _ANTHROPIC_CLIENT is None:
        _ANTHROPIC_CLIENT = _anthropic_lib.Anthropic(api_key=api_key)
    return _ANTHROPIC_CLIENT


_EXPLAIN_SYSTEM = (
    "You are a senior network security engineer. When given a Cisco device config diff "
    "result — including a numeric risk score, per-level change counts, and a list of "
    "annotated diff entries — you produce a concise, plain-English explanation for a "
    "network operations team. Cover: (1) the overall risk level and what is driving it, "
    "(2) the two or three most dangerous individual changes and their real-world impact, "
    "(3) a short recommended action (approve / review in staging / block immediately). "
    "Be direct and specific. Use markdown bullet points. Keep the response under 350 words."
)


def _send_email_alert(job_type: str, stats: dict, job_id: str, subject_override: str = "") -> str | None:
    """Send an HTML email summary. Returns error string or None on success."""
    if not _smtp_configured():
        return "SMTP not configured"
    non_compliant = (
        stats.get("non_compliant") or stats.get("noncompliant")
        or stats.get("psirt_non_compliant") or stats.get("bug_non_compliant") or 0
    )
    if not subject_override and non_compliant < _ALERT_MIN_NC:
        return None  # below threshold, skip quietly

    total = stats.get("total", 0)
    label = job_type.upper()
    subject = subject_override or f"[Cisco EOX Finder] {label} Alert — {non_compliant}/{total} Non-Compliant"

    # Build HTML body
    rows_html = "".join(
        f"<tr><td style='padding:4px 10px;border-bottom:1px solid #30363d'>{k}</td>"
        f"<td style='padding:4px 10px;border-bottom:1px solid #30363d;font-weight:bold'>{v}</td></tr>"
        for k, v in stats.items() if isinstance(v, (int, float, str))
    )
    body = f"""<!DOCTYPE html><html><body style='font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:1.5rem'>
<h2 style='color:#e6edf3'>{label} Job Complete — Job ID: {job_id}</h2>
<table style='border-collapse:collapse;font-size:0.85rem;min-width:320px'>
  <thead><tr><th style='text-align:left;padding:4px 10px;border-bottom:2px solid #30363d;color:#8b949e'>Stat</th>
  <th style='text-align:left;padding:4px 10px;border-bottom:2px solid #30363d;color:#8b949e'>Value</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
<p style='font-size:0.78rem;color:#6e7681;margin-top:1.5rem'>Sent by Cisco EOX Finder · Job ID {job_id}</p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = _ALERT_FROM
    msg["To"]      = _ALERT_TO
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as s:
            s.ehlo()
            if _SMTP_PORT != 465:
                s.starttls()
            if _SMTP_USER and _SMTP_PASS:
                s.login(_SMTP_USER, _SMTP_PASS)
            s.sendmail(_ALERT_FROM, [a.strip() for a in _ALERT_TO.split(",")], msg.as_string())
        return None
    except Exception as exc:
        print(f"Email alert failed: {exc}", file=sys.stderr)
        return str(exc)


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

# ── Contract coverage columns (SN2INFO) ──────────────────────────────────────
COVERAGE_COLS = [
    ("Coverage Status",   "coverage_status"),
    ("Coverage End Date", "coverage_end_date"),
    ("Contract Number",   "contract_number"),
    ("Service Level",     "service_level"),
]

# ── Bug API columns ───────────────────────────────────────────────────────────
BUG_COLS = [
    ("Bug Compliance",  "bug_compliance"),
    ("Bug Open Count",  "open_count"),
    ("Bug IDs",         "bug_ids"),
    ("Bug Fixed Count", "critical_count"),
]

# ── Urgency Score columns ─────────────────────────────────────────────────────
URGENCY_COLS = [
    ("Urgency Score", "urgency_score"),
    ("Urgency Level", "urgency_level"),
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


def _compute_urgency(row: dict) -> tuple[int, str]:
    """Compute 0-100 urgency score from EOX/PSIRT/Bug/Coverage compliance columns."""
    score = 0
    eox = str(row.get("EOX Compliance", "")).lower()
    if "noncompliant" in eox:
        score += 40
    elif "warning" in eox:
        score += 20
    if str(row.get("PSIRT Compliance", "")).lower() == "non-compliant":
        score += 30
    if str(row.get("Bug Compliance", "")).lower() == "non-compliant":
        score += 20
    if str(row.get("Coverage Status", "")).lower() == "inactive":
        score += 10
    score = min(score, 100)
    if score >= 70:
        level = "Critical"
    elif score >= 40:
        level = "High"
    elif score >= 10:
        level = "Medium"
    else:
        level = "Low"
    return score, level


def _build_bug_lookup(
    pairs: list[tuple[str, str]],
) -> dict[tuple[str, str], dict]:
    """Query Bug API for unique (pid, version) pairs. version may be empty string."""
    lookup: dict[tuple[str, str], dict] = {}
    for pid, version in pairs:
        key = (pid.upper(), version.lower())
        if key in lookup:
            continue
        try:
            rec = cisco_bug.get_bug_summary(pid, version)
            lookup[key] = rec or {}
        except Exception as exc:
            print(f"Bug lookup failed for {pid}/{version}: {exc}", file=sys.stderr)
            lookup[key] = {}
    return lookup


def _build_coverage_lookup(sns: list[str]) -> dict[str, dict]:
    """Query SN2INFO coverage/summary for unique SNs (batched 20 at a time)."""
    lookup: dict[str, dict] = {}
    batch_size = 20
    for i in range(0, len(sns), batch_size):
        batch = [s for s in sns[i:i + batch_size] if s]
        if not batch:
            continue
        try:
            result = cisco_sn2info.get_coverage_summary(batch)
            lookup.update(result)
        except Exception as exc:
            print(f"Coverage lookup failed for batch starting {batch[0]}: {exc}", file=sys.stderr)
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

/* Unified table column-type colours */
thead th.cov-col   { color: #3fb950; }
thead th.swim-col  { color: #e3b341; }
thead th.psirt-col { color: #f85149; }
thead th.bug-col     { color: #a371f7; }
thead th.urgency-col { color: #f0883e; }

/* Config Diff risk colours */
.diff-add     { background: rgba(63,185,80,0.06); }
.diff-remove  { background: rgba(248,81,73,0.06); }
.diff-sep     { background: transparent; color: #484f58; font-style: italic; }
.diff-context { color: #6e7681; }
.risk-critical{ background: rgba(248,81,73,0.18); color: #f85149; border-left: 3px solid #f85149; }
.risk-high    { background: rgba(227,130,0,0.15);  color: #e37300; border-left: 3px solid #e37300; }
.risk-medium  { background: rgba(227,179,65,0.12); color: #e3b341; border-left: 3px solid #e3b341; }
.risk-low     { background: rgba(88,166,255,0.08); color: #8b949e; border-left: 3px solid #30363d; }
.risk-badge {
  display: inline-block; padding: 0.1rem 0.45rem; border-radius: 4px;
  font-size: 0.65rem; font-weight: 700; letter-spacing: 0.4px; white-space: nowrap; margin-left: 0.5rem;
}
.rb-critical { background: rgba(248,81,73,0.2);  color: #f85149; }
.rb-high     { background: rgba(227,130,0,0.2);   color: #e37300; }
.rb-medium   { background: rgba(227,179,65,0.2);  color: #e3b341; }
.rb-low      { background: rgba(88,166,255,0.1);  color: #58a6ff; }
.diff-line-no{ color: #484f58; font-size: 0.7rem; min-width: 3.5rem; text-align: right; padding-right: 0.75rem; user-select: none; }
.diff-prefix { font-family: monospace; font-weight: 700; width: 1rem; display: inline-block; }
.diff-content{ font-family: "SF Mono","Fira Code",monospace; font-size: 0.78rem; white-space: pre-wrap; word-break: break-all; }
.risk-reason { font-size: 0.72rem; color: #8b949e; margin-left: 0.75rem; font-style: italic; }
.score-badge {
  padding: 0.35rem 1rem; border-radius: 20px; font-size: 0.85rem; font-weight: 700;
}
.score-critical { background: rgba(248,81,73,0.15);  color: #f85149; border: 1px solid rgba(248,81,73,0.4); }
.score-high     { background: rgba(227,130,0,0.15);   color: #e37300; border: 1px solid rgba(227,130,0,0.4); }
.score-medium   { background: rgba(227,179,65,0.15);  color: #e3b341; border: 1px solid rgba(227,179,65,0.4); }
.score-ok       { background: rgba(63,185,80,0.15);   color: #3fb950; border: 1px solid rgba(63,185,80,0.4); }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
</head>
<body>

<header>
  <div class="logo">Cisco <span>EOX</span> Finder</div>
  <p>End-of-Life · SWIM · PSIRT Security · Bugs · Config Diff — Cisco APIs</p>
</header>

<div class="tabs">
  <button class="tab-btn active" data-tab="single">Single Search</button>
  <button class="tab-btn" data-tab="bulk">Bulk Excel Upload</button>
  <button class="tab-btn" data-tab="swim">SWIM</button>
  <button class="tab-btn" data-tab="psirt">PSIRT</button>
  <button class="tab-btn" data-tab="unified">Unified Report</button>
  <button class="tab-btn" data-tab="bugs">Bugs</button>
  <button class="tab-btn" data-tab="configdiff">Config Diff</button>
  <button class="tab-btn" data-tab="dashboard">Dashboard</button>
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
    <a id="downloadHtmlLink" class="btn-secondary" href="#" target="_blank" style="margin-left:0.5rem">⎙ HTML Report</a>
    <button class="btn-secondary" onclick="saveCurrentList('eox')" style="margin-left:0.5rem">💾 Save List</button>
    <button class="btn-secondary" onclick="toggleEoxTimeline()" style="margin-left:0.5rem">📅 Timeline</button>
    <button class="btn-secondary" onclick="toggleMigrationAdvisor()" style="margin-left:0.5rem">🔀 Migration Advisor</button>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + EOX dates</span>
  </div>

  <div id="eoxTimelineWrap" style="max-width:1200px;margin:0 auto 1.5rem;display:none">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
        <div>
          <h3 style="margin:0;font-size:0.95rem">EOX Lifecycle Timeline</h3>
          <p style="margin:0.25rem 0 0;font-size:0.78rem;color:#8b949e">Days until Last Date of Support — top 25 devices by urgency. Red = past/critical, Amber = warning (&lt;180 days), Green = compliant.</p>
        </div>
        <div style="display:flex;gap:0.5rem">
          <button class="btn-secondary" style="font-size:0.75rem" onclick="renderEoxTimeline('ldos')">By LDoS</button>
          <button class="btn-secondary" style="font-size:0.75rem" onclick="renderEoxTimeline('eos')">By EoS</button>
        </div>
      </div>
      <div style="position:relative;height:420px">
        <canvas id="eoxTimelineChart"></canvas>
      </div>
    </div>
  </div>

  <div id="migrationAdvisorWrap" style="max-width:1200px;margin:0 auto 1.5rem;display:none">
    <div class="card">
      <h3 style="margin-top:0">Migration Advisor</h3>
      <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1rem">
        Devices past End-of-Life that have a Cisco-recommended migration path. Grouped by replacement PID to surface consolidation opportunities.
      </p>
      <div id="migrationAdvisorSummaryBar" class="summary-bar" style="margin-bottom:1rem"></div>
      <div id="migrationAdvisorContent"></div>
    </div>
  </div>

  <div id="bulkTableWrap" class="table-wrap" style="display:none">
    <table id="bulkTable">
      <thead id="bulkThead"></thead>
      <tbody id="bulkTbody"></tbody>
    </table>
    <div class="pagination" id="pagination"></div>
  </div>

  <!-- Saved Lists -->
  <div class="card" id="savedListsCard">
    <h2>Saved Device Lists</h2>
    <div id="savedListsWrap">
      <p style="color:#6e7681;font-size:0.85rem">No saved lists yet. After processing a file, click <strong>💾 Save List</strong> to save it for quick reload.</p>
    </div>
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
    <a id="swimDownloadHtmlLink" class="btn-secondary" href="#" target="_blank" style="margin-left:0.5rem">⎙ HTML Report</a>
    <button class="btn-secondary" onclick="saveCurrentList('swim')" style="margin-left:0.5rem">💾 Save List</button>
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
    <a id="psirtDownloadHtmlLink" class="btn-secondary" href="#" target="_blank" style="margin-left:0.5rem">⎙ HTML Report</a>
    <button class="btn-secondary" onclick="saveCurrentList('psirt')" style="margin-left:0.5rem">💾 Save List</button>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + PSIRT advisory data</span>
  </div>
  <div id="psirtTableWrap" class="table-wrap" style="display:none">
    <table id="psirtTable"><thead id="psirtThead"></thead><tbody id="psirtTbody"></tbody></table>
    <div class="pagination" id="psirtPagination"></div>
  </div>
</div>

<!-- ── Unified Report Tab ─────────────────────────────────────────────────── -->
<div id="tab-unified" class="tab-panel">
  <div class="card">
    <h2>Unified Report — EOX + Coverage + SWIM + PSIRT + Bugs</h2>
    <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1rem">Upload one spreadsheet to enrich it with all five data sources at once.</p>
    <div class="drop-zone" id="unifiedDropZone">
      <div class="drop-icon">📋</div>
      <p>Drag &amp; drop your Excel file here, or click to browse</p>
      <p style="font-size:0.75rem;color:#6e7681">.xlsx / .csv · needs at least a PID or Serial Number column</p>
      <input type="file" id="unifiedFileInput" accept=".xlsx,.xls,.csv" style="display:none">
    </div>
    <div id="unifiedDetectedCols" style="display:none;margin-bottom:1rem;">
      <span style="font-size:0.8rem;color:#8b949e">Detected: </span>
      <span id="unifiedColPid"     style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span id="unifiedColSn"      style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span id="unifiedColVersion" style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span id="unifiedColOsType"  style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
    </div>
    <div class="progress-wrap" id="unifiedProgressWrap">
      <div class="progress-bar-bg"><div class="progress-bar-fill" id="unifiedProgressFill" style="width:0%"></div></div>
      <div class="progress-text" id="unifiedProgressText">Processing…</div>
    </div>
    <div id="unifiedColMappingWrap" style="display:none">
      <p style="font-size:0.85rem;color:#8b949e;margin-bottom:0.75rem">Could not auto-detect a PID or Serial Number column. Select below:</p>
      <div class="form-row">
        <div><label>PID / Product ID Column (optional)</label><select id="unifiedManualPidSel"></select></div>
        <div><label>Serial Number Column (optional)</label><select id="unifiedManualSnSel"></select></div>
      </div>
      <div class="form-row">
        <div><label>Software Version Column (optional)</label><select id="unifiedManualVersionSel"></select></div>
        <div><label>OS Type Column (optional)</label><select id="unifiedManualOsTypeSel"></select></div>
      </div>
      <div style="margin-bottom:0.75rem">
        <label>Default OS Type (used when no OS Type column)</label>
        <select id="unifiedDefaultOsTypeSel">
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
        <button class="btn-primary" onclick="unifiedResubmitWithMapping()">Process with Selected Columns</button>
      </div>
    </div>
    <div class="btn-row">
      <button id="unifiedUploadBtn" class="btn-primary" disabled>Process File</button>
      <button id="unifiedClearUploadBtn" class="btn-secondary">Clear</button>
      <span id="unifiedUploadStatus" class="status-msg"></span>
    </div>
  </div>

  <!-- Import from NetBox / ServiceNow -->
  <div class="card" style="margin-top:1rem">
    <h3 style="margin-top:0;font-size:0.95rem">Import from NetBox or ServiceNow</h3>
    <p style="font-size:0.82rem;color:#8b949e;margin:0 0 1rem">Fetch devices directly from your CMDB — no spreadsheet needed. The imported list is loaded into the drop zone above and auto-processed.</p>

    <div style="display:flex;gap:0.5rem;margin-bottom:1rem">
      <button class="btn-secondary" style="font-size:0.8rem" onclick="toggleImportSection('netbox')">NetBox</button>
      <button class="btn-secondary" style="font-size:0.8rem" onclick="toggleImportSection('servicenow')">ServiceNow</button>
    </div>

    <div id="importNetboxForm" style="display:none;padding:0.75rem;background:#0d1117;border-radius:6px;border:1px solid #30363d;margin-bottom:0.75rem">
      <div class="form-row">
        <div>
          <label>NetBox URL</label>
          <input type="text" id="nbUrl" placeholder="https://netbox.example.com" autocomplete="off">
        </div>
        <div>
          <label>API Token</label>
          <input type="password" id="nbToken" placeholder="Token …" autocomplete="off">
        </div>
      </div>
      <div style="display:flex;gap:0.5rem;align-items:center;margin-top:0.5rem">
        <label style="font-size:0.8rem;white-space:nowrap">Max devices:</label>
        <input type="number" id="nbLimit" value="200" min="1" max="1000" style="width:80px;font-size:0.8rem;padding:0.3rem 0.5rem">
        <button class="btn-primary" style="font-size:0.8rem" onclick="runImport('netbox')">Import</button>
        <span id="nbStatus" class="status-msg"></span>
      </div>
    </div>

    <div id="importSnowForm" style="display:none;padding:0.75rem;background:#0d1117;border-radius:6px;border:1px solid #30363d;margin-bottom:0.75rem">
      <div class="form-row">
        <div>
          <label>ServiceNow URL</label>
          <input type="text" id="snowUrl" placeholder="https://instance.service-now.com" autocomplete="off">
        </div>
        <div>
          <label>CMDB Table</label>
          <input type="text" id="snowTable" value="cmdb_ci_ip_switch" autocomplete="off">
          <div class="hint">e.g. cmdb_ci_ip_switch · cmdb_ci_ip_router</div>
        </div>
      </div>
      <div class="form-row">
        <div>
          <label>Username</label>
          <input type="text" id="snowUser" autocomplete="off">
        </div>
        <div>
          <label>Password</label>
          <input type="password" id="snowPass" autocomplete="off">
        </div>
      </div>
      <div style="display:flex;gap:0.5rem;align-items:center;margin-top:0.5rem">
        <label style="font-size:0.8rem;white-space:nowrap">Max records:</label>
        <input type="number" id="snowLimit" value="200" min="1" max="1000" style="width:80px;font-size:0.8rem;padding:0.3rem 0.5rem">
        <button class="btn-primary" style="font-size:0.8rem" onclick="runImport('servicenow')">Import</button>
        <span id="snowStatus" class="status-msg"></span>
      </div>
    </div>
  </div>

  <div id="unifiedSummaryBar"  class="summary-bar"                        style="display:none"></div>
  <div id="unifiedDownloadBar" style="max-width:1200px;margin:0 auto 1rem;display:none">
    <a id="unifiedDownloadLink" class="btn-green" href="#">⬇ Download Unified Report</a>
    <a id="unifiedDownloadHtmlLink" class="btn-secondary" href="#" target="_blank" style="margin-left:0.5rem">⎙ HTML Report</a>
    <button class="btn-secondary" onclick="saveCurrentList('unified')" style="margin-left:0.5rem">💾 Save List</button>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + EOX · Coverage · SWIM · PSIRT · Bug data</span>
  </div>
  <div id="unifiedTableWrap" class="table-wrap" style="display:none">
    <table id="unifiedTable"><thead id="unifiedThead"></thead><tbody id="unifiedTbody"></tbody></table>
    <div class="pagination" id="unifiedPagination"></div>
  </div>
</div>

<!-- ── Bugs Tab ── -->
<div id="tab-bugs" class="tab-panel">

  <!-- Single search -->
  <div class="card">
    <h2>Bugs — Known Defect Lookup</h2>
    <form id="bugSearchForm">
      <div class="form-row">
        <div>
          <label for="bugPid">Product ID (Base PID)</label>
          <input type="text" id="bugPid" placeholder="e.g. WS-C3560-48PS-S" autocomplete="off">
          <div class="hint">Single exact PID — no wildcards or commas</div>
        </div>
        <div>
          <label for="bugVersion">Software Version (optional)</label>
          <input type="text" id="bugVersion" placeholder="e.g. 12.2(25)SEE2" autocomplete="off">
          <div class="hint">If provided, shows only bugs affecting this release</div>
        </div>
      </div>
      <div class="btn-row">
        <button type="submit" id="bugSearchBtn" class="btn-primary">Find Bugs</button>
        <button type="button" id="bugClearBtn" class="btn-secondary">Clear</button>
        <span id="bugSearchStatus" class="status-msg"></span>
      </div>
    </form>
  </div>
  <div id="bugResults"></div>

  <!-- Bulk upload -->
  <div class="card">
    <h2>Bug Bulk Upload</h2>
    <div class="drop-zone" id="bugDropZone">
      <div class="drop-icon">🐛</div>
      <p>Drag &amp; drop your Excel file here, or click to browse</p>
      <p style="font-size:0.75rem;color:#6e7681">.xlsx / .csv · detects "Product Part" and optionally "Current Version"</p>
      <input type="file" id="bugFileInput" accept=".xlsx,.xls,.csv" style="display:none">
    </div>
    <div id="bugDetectedCols" style="display:none;margin-bottom:1rem;">
      <span style="font-size:0.8rem;color:#8b949e">Detected columns: </span>
      <span id="bugColPid"     style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
      <span style="font-size:0.8rem;color:#6e7681"> · </span>
      <span id="bugColVersion" style="font-size:0.8rem;color:#3fb950;font-family:monospace"></span>
    </div>
    <div class="progress-wrap" id="bugProgressWrap">
      <div class="progress-bar-bg"><div class="progress-bar-fill" id="bugProgressFill" style="width:0%"></div></div>
      <div class="progress-text" id="bugProgressText">Processing…</div>
    </div>
    <div id="bugColMappingWrap" style="display:none">
      <p style="font-size:0.85rem;color:#8b949e;margin-bottom:0.75rem">Could not auto-detect columns. Select the correct ones below:</p>
      <div class="form-row">
        <div><label>Product ID Column</label><select id="bugManualPidSel"></select></div>
        <div><label>Current Version Column (optional)</label><select id="bugManualVersionSel"></select></div>
      </div>
      <div class="btn-row" style="margin-top:0.75rem">
        <button class="btn-primary" onclick="bugResubmitWithMapping()">Process with Selected Columns</button>
      </div>
    </div>
    <div class="btn-row">
      <button id="bugUploadBtn" class="btn-primary" disabled>Process File</button>
      <button id="bugClearUploadBtn" class="btn-secondary">Clear</button>
      <span id="bugUploadStatus" class="status-msg"></span>
    </div>
  </div>

  <div id="bugSummaryBar"  class="summary-bar"                        style="display:none"></div>
  <div id="bugDownloadBar" style="max-width:1200px;margin:0 auto 1rem;display:none">
    <a id="bugDownloadLink" class="btn-green" href="#">⬇ Download Enriched Excel</a>
    <a id="bugDownloadHtmlLink" class="btn-secondary" href="#" target="_blank" style="margin-left:0.5rem">⎙ HTML Report</a>
    <button class="btn-secondary" onclick="saveCurrentList('bug')" style="margin-left:0.5rem">💾 Save List</button>
    <span style="font-size:0.8rem;color:#6e7681;margin-left:0.75rem">Includes all original columns + Bug compliance data</span>
  </div>
  <div id="bugTableWrap" class="table-wrap" style="display:none">
    <table id="bugTable"><thead id="bugThead"></thead><tbody id="bugTbody"></tbody></table>
    <div class="pagination" id="bugPagination"></div>
  </div>
</div>

<!-- ── Config Diff Tab ── -->
<div id="tab-configdiff" class="tab-panel">
  <div class="card">
    <h2>Config Diff — Risk Analyzer</h2>
    <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1rem">
      Paste or upload two configurations. Each changed line is classified by risk level so you can immediately see what could cause outages or security regressions.
    </p>

    <div class="form-row">
      <div>
        <label for="refConfig">Reference Config <span style="font-weight:400;color:#6e7681">(startup / baseline)</span></label>
        <textarea id="refConfig" rows="12" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-family:'SF Mono','Fira Code',monospace;font-size:0.78rem;padding:0.6rem 0.75rem;resize:vertical" placeholder="Paste startup/reference config here…&#10;&#10;Or upload a file →"></textarea>
        <div style="margin-top:0.4rem;display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
          <label class="btn-secondary" style="cursor:pointer;padding:0.35rem 0.75rem;font-size:0.8rem">
            📂 Upload File <input type="file" id="refConfigFile" accept=".txt,.cfg,.conf,.log" style="display:none">
          </label>
          <button class="btn-secondary" style="font-size:0.8rem;padding:0.35rem 0.75rem" onclick="loadDiffSample('ref')">Load Sample</button>
          <select id="baselineLoadSel" style="font-size:0.8rem;padding:0.35rem 0.5rem;max-width:180px" onchange="loadBaselineIntoRef()">
            <option value="">Load saved baseline…</option>
          </select>
          <button class="btn-secondary" style="font-size:0.8rem;padding:0.35rem 0.75rem" onclick="saveRefAsBaseline()">💾 Save as Baseline</button>
          <span id="refFileName" style="font-size:0.75rem;color:#6e7681"></span>
        </div>
      </div>
      <div>
        <label for="curConfig">Current Config <span style="font-weight:400;color:#6e7681">(running / proposed)</span></label>
        <textarea id="curConfig" rows="12" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-family:'SF Mono','Fira Code',monospace;font-size:0.78rem;padding:0.6rem 0.75rem;resize:vertical" placeholder="Paste running/current config here…&#10;&#10;Or upload a file →"></textarea>
        <div style="margin-top:0.4rem;display:flex;gap:0.5rem;align-items:center">
          <label class="btn-secondary" style="cursor:pointer;padding:0.35rem 0.75rem;font-size:0.8rem">
            📂 Upload File <input type="file" id="curConfigFile" accept=".txt,.cfg,.conf,.log" style="display:none">
          </label>
          <button class="btn-secondary" style="font-size:0.8rem;padding:0.35rem 0.75rem" onclick="loadDiffSample('cur')">Load Sample</button>
          <span id="curFileName" style="font-size:0.75rem;color:#6e7681"></span>
        </div>
      </div>
    </div>

    <div style="margin-bottom:1rem">
      <label style="display:inline;margin-right:0.5rem">Minimum Risk Level:</label>
      <select id="diffMinRisk" style="width:auto;display:inline-block;padding:0.4rem 0.75rem">
        <option value="info">Show All</option>
        <option value="low">Low and above</option>
        <option value="medium">Medium and above</option>
        <option value="high">High and above</option>
        <option value="critical">Critical only</option>
      </select>
    </div>

    <div class="btn-row">
      <button id="diffAnalyzeBtn" class="btn-primary">Analyze Risk</button>
      <button class="btn-secondary" onclick="clearDiff()">Clear</button>
      <span id="diffStatus" class="status-msg"></span>
    </div>
  </div>

  <div id="diffSummaryBar" class="summary-bar" style="display:none"></div>

  <div id="diffDownloadBar" style="max-width:1200px;margin:0 auto 1rem;display:none;gap:0.5rem;flex-wrap:wrap">
    <a id="diffDownloadHtml" class="btn-secondary" href="#" onclick="downloadDiffReport();return false">⎙ Download HTML Report</a>
    <button id="diffExplainBtn" class="btn-secondary" onclick="explainDiff()" style="border-color:#388bfd;color:#388bfd">💡 Explain Risk</button>
  </div>
  <div id="diffExplainWrap" style="max-width:1200px;margin:0 auto 1rem;display:none">
    <div class="card" style="border-color:#388bfd44">
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem">
        <span style="font-weight:700;color:#388bfd">AI Risk Explanation</span>
        <span style="font-size:0.75rem;color:#6e7681">Powered by Claude</span>
        <span id="diffExplainSpinner" style="display:none;color:#8b949e;font-size:0.8rem">Analyzing…</span>
      </div>
      <div id="diffExplainContent" style="font-size:0.85rem;line-height:1.6;white-space:pre-wrap;color:#c9d1d9"></div>
    </div>
  </div>

  <div id="diffResultWrap" style="max-width:1200px;margin:0 auto 1.5rem;display:none">
    <div class="card" style="padding:0;overflow:hidden">
      <table id="diffTable" style="width:100%;border-collapse:collapse;font-size:0.78rem">
        <thead id="diffThead"></thead>
        <tbody id="diffTbody"></tbody>
      </table>
    </div>
  </div>

  <!-- ── Bulk Config Diff second card ── -->
  <div style="max-width:1200px;margin:0 auto 1.5rem">
    <div class="card">
      <h3 style="margin-top:0">Bulk Config Diff — ZIP Upload</h3>
      <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1rem">
        Upload a <strong>.zip</strong> containing multiple config files. One file is the baseline; all others are diffed against it. Files named <code>baseline.cfg</code> or <code>reference.cfg</code> are auto-detected.
      </p>

      <div class="drop-zone" id="bulkDiffDropZone" ondragover="event.preventDefault()" ondrop="bulkDiffOnDrop(event)">
        Drop a <strong>.zip</strong> file here or
        <label style="cursor:pointer;color:#58a6ff;text-decoration:underline">click to browse
          <input type="file" id="bulkDiffZipInput" accept=".zip" style="display:none">
        </label>
      </div>

      <div id="bulkDiffBaselineWrap" style="display:none;margin-top:0.75rem;padding:0.75rem;background:#161b22;border-radius:6px;border:1px solid #30363d">
        <label style="font-weight:600">No baseline auto-detected — select the baseline file:</label>
        <div style="display:flex;gap:0.5rem;align-items:center;margin-top:0.5rem">
          <select id="bulkDiffBaselineSel" style="flex:1;padding:0.4rem 0.75rem"></select>
          <button class="btn-primary" onclick="resubmitBulkDiff()">Analyze</button>
        </div>
      </div>

      <div style="margin-top:0.75rem">
        <span id="bulkDiffStatus" class="status-msg"></span>
        <div id="bulkDiffProgressWrap" style="display:none;margin-top:0.5rem">
          <div class="progress-bar"><div class="progress-fill" style="width:60%"></div></div>
          <span style="font-size:0.8rem;color:#8b949e">Analyzing configs…</span>
        </div>
      </div>

      <div id="bulkDiffSummaryBar" class="summary-bar" style="display:none"></div>

      <div id="bulkDiffDownloadBar" style="display:none;margin-top:0.75rem">
        <a id="bulkDiffDownloadLink" class="btn-secondary" href="#">⬇ Download Excel Summary</a>
      </div>

      <div id="bulkDiffTableWrap" class="table-wrap" style="display:none">
        <table style="width:100%;border-collapse:collapse;font-size:0.78rem">
          <thead><tr style="background:#161b22">
            <th style="text-align:left;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d">Device</th>
            <th style="text-align:left;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d">Filename</th>
            <th style="text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d">Score</th>
            <th style="text-align:left;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d">Level</th>
            <th style="text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d;color:#f85149">Crit</th>
            <th style="text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d;color:#d29922">High</th>
            <th style="text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d;color:#388bfd">Med</th>
            <th style="text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d;color:#3fb950">Low</th>
            <th style="text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid #30363d">Changes</th>
            <th style="padding:0.5rem 0.75rem;border-bottom:1px solid #30363d">Report</th>
          </tr></thead>
          <tbody id="bulkDiffTbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── Saved Baselines management card ── -->
  <div style="max-width:1200px;margin:0 auto 1.5rem">
    <div class="card">
      <h3 style="margin-top:0">Saved Config Baselines</h3>
      <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1rem">
        Named baseline configs stored on the server. Load one into the Reference pane above without re-pasting.
      </p>
      <div id="baselinesListWrap">
        <p style="color:#6e7681;font-size:0.85rem">No baselines saved yet. Paste a config in the Reference pane above and click <strong>💾 Save as Baseline</strong>.</p>
      </div>
    </div>
  </div>
</div>

<!-- ── Dashboard Tab ── -->
<div id="tab-dashboard" class="tab-panel">
  <div class="card">
    <h2>Compliance Dashboard</h2>
    <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1.5rem">Aggregate view across all processed jobs (last 90).</p>
    <div id="dashboardEmpty" style="color:#6e7681;font-size:0.85rem">No jobs recorded yet. Process a file from any tab to see data here.</div>
    <div id="dashboardCharts" style="display:none">
      <div style="display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:2rem">
        <div style="flex:1;min-width:260px;max-width:340px">
          <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">EOX Compliance (all EOX jobs)</h3>
          <canvas id="dashEoxDonut" height="200"></canvas>
        </div>
        <div style="flex:1;min-width:260px;max-width:340px">
          <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">PSIRT Compliance (all PSIRT / Unified jobs)</h3>
          <canvas id="dashPsirtDonut" height="200"></canvas>
        </div>
        <div style="flex:1;min-width:260px;max-width:340px">
          <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">Coverage Status (all Unified jobs)</h3>
          <canvas id="dashCovDonut" height="200"></canvas>
        </div>
        <div style="flex:1;min-width:260px;max-width:340px">
          <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">Bug Compliance (all Bug / Unified jobs)</h3>
          <canvas id="dashBugDonut" height="200"></canvas>
        </div>
        <div style="flex:1;min-width:260px;max-width:340px">
          <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">Urgency Distribution (Unified jobs)</h3>
          <canvas id="dashUrgencyDonut" height="200"></canvas>
        </div>
      </div>
      <div style="margin-bottom:2rem">
        <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">Jobs Over Time (rows processed per upload)</h3>
        <canvas id="dashTrendBar" height="120"></canvas>
      </div>
      <div style="margin-bottom:2rem">
        <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">Non-Compliant Trend (per job, last 90 days)</h3>
        <p style="font-size:0.78rem;color:#6e7681;margin:0 0 0.75rem">Each point = one bulk job. Shows how many non-compliant devices were found at that moment in time.</p>
        <canvas id="dashNcTrend" height="140"></canvas>
      </div>
      <div id="dashJobTable" style="overflow-x:auto"></div>
    </div>
  </div>

  <!-- Email alert settings card -->
  <div class="card" style="margin-top:1.5rem">
    <h3 style="margin-top:0">Email Alert Settings</h3>
    <p style="font-size:0.85rem;color:#8b949e;margin:0 0 1rem">
      Sends an HTML summary email after each bulk job when non-compliant devices are found.
      Configure via environment variables — no restart needed after initial setup.
    </p>
    <div id="emailConfigDisplay" style="font-size:0.82rem;margin-bottom:1rem"></div>
    <div style="display:flex;gap:0.5rem;align-items:center">
      <button class="btn-secondary" onclick="sendTestEmail()">✉ Send Test Email</button>
      <span id="emailTestStatus" class="status-msg"></span>
    </div>
    <div style="margin-top:1rem;padding:0.75rem;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-size:0.78rem;color:#6e7681">
      <strong style="color:#8b949e">Required env vars:</strong><br>
      <code>SMTP_HOST</code>, <code>SMTP_PORT</code> (default 587), <code>SMTP_USER</code>, <code>SMTP_PASS</code>,
      <code>ALERT_EMAIL_FROM</code>, <code>ALERT_EMAIL_TO</code> (comma-separated),
      <code>ALERT_MIN_NONCOMPLIANT</code> (default 1)
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>

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

    document.getElementById('downloadLink').href     = `/download/${data.job_id}`;
    document.getElementById('downloadHtmlLink').href = `/html/${data.job_id}`;
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

// ── EOX Timeline Chart ────────────────────────────────────────────────────────
let _eoxTimelineChart = null;

function toggleEoxTimeline() {
  const wrap = document.getElementById('eoxTimelineWrap');
  if (wrap.style.display === 'none') {
    wrap.style.display = 'block';
    renderEoxTimeline('ldos');
  } else {
    wrap.style.display = 'none';
  }
}

function renderEoxTimeline(mode) {
  const today = Date.now();
  const MS_PER_DAY = 86400000;
  const WARN_DAYS  = 180;

  const dateCol = mode === 'eos' ? 'EOX End of Sale' : 'EOX Last Date of Support';
  const pidCol  = bulkHeaders.find(h => !eoxColNames.includes(h) && h !== '');

  // Build dataset: devices that have the requested date
  let items = bulkRows
    .map(row => {
      const label = pidCol ? String(row[pidCol] || '').trim() : '';
      const raw   = String(row[dateCol] || '').trim();
      if (!raw || raw === 'N/A') return null;
      const ts = Date.parse(raw);
      if (isNaN(ts)) return null;
      const days = Math.round((ts - today) / MS_PER_DAY);
      return { label: label || raw, days, ts };
    })
    .filter(Boolean);

  // Sort ascending (most urgent first), cap at 25
  items.sort((a, b) => a.days - b.days);
  items = items.slice(0, 25);

  const labels = items.map(d => d.label);
  const data   = items.map(d => d.days);
  const colors = data.map(d =>
    d < 0          ? '#f85149' :
    d < WARN_DAYS  ? '#e3b341' : '#3fb950'
  );

  const ctx = document.getElementById('eoxTimelineChart').getContext('2d');
  if (_eoxTimelineChart) _eoxTimelineChart.destroy();
  _eoxTimelineChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: dateCol,
        data,
        backgroundColor: colors,
        borderRadius: 3,
        borderSkipped: false,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => {
              const d = ctx.parsed.x;
              if (d < 0) return `${Math.abs(d)} days past (${dateCol})`;
              return `${d} days remaining (${dateCol})`;
            }
          }
        }
      },
      scales: {
        x: {
          ticks: {
            color: '#8b949e',
            callback: v => v === 0 ? 'Today' : `${v > 0 ? '+' : ''}${v}d`,
          },
          grid: { color: '#21262d' },
          title: { display: true, text: 'Days from Today', color: '#6e7681' }
        },
        y: {
          ticks: { color: '#c9d1d9', font: { size: 11 } },
          grid: { color: '#21262d' }
        }
      }
    }
  });
}

// ── Migration Advisor ─────────────────────────────────────────────────────────
function toggleMigrationAdvisor() {
  const wrap = document.getElementById('migrationAdvisorWrap');
  if (wrap.style.display === 'none') {
    wrap.style.display = 'block';
    renderMigrationAdvisor();
  } else {
    wrap.style.display = 'none';
  }
}

function renderMigrationAdvisor() {
  const pidCol        = bulkHeaders.find(h => !eoxColNames.includes(h) && h !== '');
  const complianceCol = 'EOX Compliance';
  const migCol        = 'EOX Migration PID';
  const migInfoKey    = null; // migration_info not stored as separate column

  // Build list of EoL devices with a migration target
  const eolDevices = bulkRows.filter(row => {
    const comp = String(row[complianceCol] || '').toLowerCase();
    const mig  = String(row[migCol] || '').trim();
    return (comp.includes('noncompliant') || comp.includes('warning')) && mig;
  });

  const summaryBar = document.getElementById('migrationAdvisorSummaryBar');
  const content    = document.getElementById('migrationAdvisorContent');

  if (!eolDevices.length) {
    summaryBar.innerHTML = '';
    content.innerHTML = '<p style="color:#6e7681;font-size:0.85rem">No EoL / warning devices with a migration path found in the current dataset.</p>';
    return;
  }

  // Group by migration target PID
  const groups = {};
  for (const row of eolDevices) {
    const mig = String(row[migCol]).trim();
    if (!groups[mig]) groups[mig] = [];
    groups[mig].push(row);
  }
  const sortedTargets = Object.keys(groups).sort((a, b) => groups[b].length - groups[a].length);

  const totalEol = eolDevices.length;
  const uniqueTargets = sortedTargets.length;
  summaryBar.innerHTML = `
    <span class="pill pill-nc">${totalEol} EoL / Warning Devices</span>
    <span class="pill pill-total">${uniqueTargets} Unique Migration Target${uniqueTargets !== 1 ? 's' : ''}</span>`;

  content.innerHTML = sortedTargets.map(target => {
    const devs = groups[target];
    const rows = devs.map(row => {
      const dev = pidCol ? String(row[pidCol] || '').trim() : '—';
      const comp = String(row[complianceCol] || '');
      const badge = eoxComplianceBadge(comp);
      return `<tr style="border-bottom:1px solid #21262d">
        <td style="padding:0.35rem 0.75rem;font-family:monospace;font-size:0.8rem">${dev}</td>
        <td style="padding:0.35rem 0.75rem">${badge}</td>
      </tr>`;
    }).join('');

    return `<div style="margin-bottom:1.25rem;border:1px solid #30363d;border-radius:6px;overflow:hidden">
      <div style="background:#161b22;padding:0.6rem 0.75rem;display:flex;align-items:center;justify-content:space-between">
        <div>
          <span style="font-size:0.75rem;color:#6e7681;margin-right:0.5rem">Migrate to →</span>
          <strong style="font-family:monospace;color:#58a6ff;font-size:0.9rem">${target}</strong>
          <span style="font-size:0.75rem;color:#6e7681;margin-left:0.75rem">${devs.length} device${devs.length !== 1 ? 's' : ''}</span>
        </div>
        <div style="display:flex;gap:0.4rem">
          <button class="btn-secondary" style="font-size:0.72rem;padding:0.2rem 0.5rem"
            onclick="document.getElementById('pid').value='${target}';document.querySelector('.tab-btn[data-tab=single]').click();searchForm.dispatchEvent(new Event('submit'))">
            EOX Lookup
          </button>
          <button class="btn-secondary" style="font-size:0.72rem;padding:0.2rem 0.5rem"
            onclick="document.getElementById('swimPid').value='${target}';document.querySelector('.tab-btn[data-tab=swim]').click();document.getElementById('swimSearchForm').dispatchEvent(new Event('submit'))">
            SWIM Lookup
          </button>
        </div>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:0.78rem">
        <thead><tr style="background:#0d1117">
          <th style="padding:0.35rem 0.75rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d">Current Device</th>
          <th style="padding:0.35rem 0.75rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d">EOX Status</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }).join('');
}

// ── Saved Config Baselines ────────────────────────────────────────────────────
let _baselines = [];

async function refreshBaselines() {
  try {
    _baselines = await (await fetch('/config-diff/baselines')).json();
  } catch(e) { _baselines = []; }

  // Update dropdown
  const sel = document.getElementById('baselineLoadSel');
  sel.innerHTML = '<option value="">Load saved baseline…</option>' +
    _baselines.map(b => `<option value="${b.baseline_id}">${b.name}</option>`).join('');

  // Update management card
  const wrap = document.getElementById('baselinesListWrap');
  if (!_baselines.length) {
    wrap.innerHTML = '<p style="color:#6e7681;font-size:0.85rem">No baselines saved yet. Paste a config in the Reference pane above and click <strong>💾 Save as Baseline</strong>.</p>';
    return;
  }
  wrap.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:0.82rem">
    <thead><tr style="background:#161b22">
      <th style="text-align:left;padding:0.4rem 0.75rem;border-bottom:1px solid #30363d">Name</th>
      <th style="text-align:left;padding:0.4rem 0.75rem;border-bottom:1px solid #30363d">Saved</th>
      <th style="padding:0.4rem 0.75rem;border-bottom:1px solid #30363d">Actions</th>
    </tr></thead>
    <tbody>${_baselines.map(b => `<tr style="border-bottom:1px solid #21262d">
      <td style="padding:0.4rem 0.75rem;font-weight:600">${b.name}</td>
      <td style="padding:0.4rem 0.75rem;color:#6e7681;font-size:0.75rem">${new Date(b.created_at*1000).toLocaleString()}</td>
      <td style="padding:0.4rem 0.75rem;display:flex;gap:0.4rem">
        <button class="btn-secondary" style="font-size:0.72rem;padding:0.2rem 0.5rem"
          onclick="loadBaselineById('${b.baseline_id}')">Load into Ref</button>
        <button class="btn-secondary" style="font-size:0.72rem;padding:0.2rem 0.5rem;color:#f85149"
          onclick="deleteBaseline('${b.baseline_id}')">Delete</button>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function loadBaselineIntoRef() {
  const sel = document.getElementById('baselineLoadSel');
  if (!sel.value) return;
  await loadBaselineById(sel.value);
  sel.value = '';
}

async function loadBaselineById(bid) {
  try {
    const b = await (await fetch(`/config-diff/baselines/${bid}`)).json();
    document.getElementById('refConfig').value = b.content;
    document.getElementById('refFileName').textContent = `Loaded: ${b.name}`;
  } catch(e) { alert('Failed to load baseline: ' + e.message); }
}

async function saveRefAsBaseline() {
  const content = document.getElementById('refConfig').value.trim();
  if (!content) { alert('Reference config pane is empty.'); return; }
  const name = prompt('Name for this baseline:');
  if (!name?.trim()) return;
  try {
    await fetch('/config-diff/baselines', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: name.trim(), content}),
    });
    await refreshBaselines();
  } catch(e) { alert('Save failed: ' + e.message); }
}

async function deleteBaseline(bid) {
  if (!confirm('Delete this baseline?')) return;
  try {
    await fetch(`/config-diff/baselines/${bid}`, {method: 'DELETE'});
    await refreshBaselines();
  } catch(e) { alert('Delete failed: ' + e.message); }
}

// Load baselines when Config Diff tab is opened
document.querySelector('.tab-btn[data-tab="configdiff"]').addEventListener('click', refreshBaselines);
refreshBaselines();  // also load on page init so dropdown is populated immediately

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

    document.getElementById('swimDownloadLink').href     = `/swim/download/${data.job_id}`;
    document.getElementById('swimDownloadHtmlLink').href = `/swim/html/${data.job_id}`;
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
        <th style="padding:0.4rem 0.6rem;border-bottom:1px solid #30363d"></th>
      </tr></thead><tbody>`;
    for (const a of advs) {
      const cveList = a.cves || [];
      const cves    = cveList.join(', ') || 'N/A';
      const url     = a.publication_url
        ? `<a href="${a.publication_url}" target="_blank" style="color:#58a6ff;font-family:monospace;font-size:0.78rem">${a.advisory_id}</a>`
        : `<span style="font-family:monospace">${a.advisory_id}</span>`;
      const nvdBtn  = cveList.length
        ? `<button class="btn-secondary" style="font-size:0.7rem;padding:0.15rem 0.4rem;white-space:nowrap"
             onclick="lookupNvd(${JSON.stringify(cveList)},this)">🔍 NVD</button>`
        : '';
      html += `<tr style="border-bottom:1px solid #21262d">
        <td style="padding:0.4rem 0.6rem">${psirtSirBadge(a.sir)}</td>
        <td style="padding:0.4rem 0.6rem;color:#c9d1d9;max-width:320px;overflow:hidden;text-overflow:ellipsis" title="${a.title.replace(/"/g,'&quot;')}">${a.title}</td>
        <td style="padding:0.4rem 0.6rem;white-space:nowrap">${url}</td>
        <td style="padding:0.4rem 0.6rem;color:#8b949e;font-family:monospace">${a.cvss_score || 'N/A'}</td>
        <td style="padding:0.4rem 0.6rem;color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${cves}">${cves}</td>
        <td style="padding:0.4rem 0.6rem;color:#8b949e;white-space:nowrap;font-family:monospace">${(a.first_published||'').slice(0,10)||'N/A'}</td>
        <td style="padding:0.4rem 0.6rem">${nvdBtn}</td>
      </tr>
      <tr class="nvd-detail-row" style="display:none"><td colspan="7" style="padding:0;background:#0d1117"></td></tr>`;
    }
    html += '</tbody></table></div>';
  }
  html += '</div>';
  psirtResultsDiv.innerHTML = html;
}

// ── NVD CVE Deep-Dive ────────────────────────────────────────────────────────
async function lookupNvd(cves, btn) {
  const detailRow = btn.closest('tr').nextElementSibling;
  if (!detailRow?.classList.contains('nvd-detail-row')) return;

  // Toggle if already loaded
  if (detailRow.style.display !== 'none') { detailRow.style.display = 'none'; btn.textContent = '🔍 NVD'; return; }

  btn.textContent = '…';
  btn.disabled    = true;
  try {
    const resp = await fetch('/nvd/cve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({cves}),
    });
    const data = await resp.json();
    if (data.error) { btn.textContent = '🔍 NVD'; btn.disabled = false; alert(data.error); return; }

    const sevColor = s => s === 'CRITICAL' ? '#f85149' : s === 'HIGH' ? '#d29922' : s === 'MEDIUM' ? '#388bfd' : '#3fb950';

    const rows = data.results.map(c => {
      if (c.error) return `<tr><td colspan="5" style="padding:0.4rem 0.75rem;color:#f85149;font-family:monospace">${c.cve_id}: ${c.error}</td></tr>`;
      const sc = c.severity ? sevColor(c.severity.toUpperCase()) : '#6e7681';
      const refs = (c.references || []).map(r => `<a href="${r}" target="_blank" style="color:#58a6ff;font-size:0.72rem;display:block;word-break:break-all">${r}</a>`).join('');
      return `<tr style="border-bottom:1px solid #21262d;vertical-align:top">
        <td style="padding:0.4rem 0.75rem;white-space:nowrap">
          <a href="${c.nvd_url}" target="_blank" style="color:#58a6ff;font-family:monospace;font-size:0.78rem">${c.cve_id}</a>
        </td>
        <td style="padding:0.4rem 0.75rem">
          <span style="background:${sc}22;color:${sc};padding:0.1rem 0.4rem;border-radius:3px;font-size:0.72rem;font-weight:700">${c.severity||'—'}</span>
          ${c.cvss_v3!=null?`<span style="margin-left:0.4rem;font-family:monospace;font-size:0.78rem">CVSSv3: ${c.cvss_v3}</span>`:''}
          ${c.cvss_v2!=null&&c.cvss_v3==null?`<span style="margin-left:0.4rem;font-family:monospace;font-size:0.78rem">CVSSv2: ${c.cvss_v2}</span>`:''}
        </td>
        <td style="padding:0.4rem 0.75rem;color:#8b949e;font-size:0.75rem;max-width:400px">${(c.description||'').substring(0,300)}${(c.description||'').length>300?'…':''}</td>
        <td style="padding:0.4rem 0.75rem;color:#6e7681;font-family:monospace;font-size:0.72rem;white-space:nowrap">
          ${c.published||'—'}<br>mod ${c.modified||'—'}
        </td>
        <td style="padding:0.4rem 0.75rem">${refs}</td>
      </tr>`;
    }).join('');

    detailRow.querySelector('td').innerHTML = `
      <div style="padding:0.5rem 0.75rem;border-top:1px solid #30363d">
        <span style="font-size:0.75rem;color:#8b949e;font-weight:600">NVD Detail</span>
        <table style="width:100%;border-collapse:collapse;font-size:0.78rem;margin-top:0.5rem">
          <thead><tr style="background:#0d1117">
            <th style="text-align:left;padding:0.3rem 0.75rem;color:#6e7681;border-bottom:1px solid #21262d;white-space:nowrap">CVE ID</th>
            <th style="text-align:left;padding:0.3rem 0.75rem;color:#6e7681;border-bottom:1px solid #21262d">Severity / CVSS</th>
            <th style="text-align:left;padding:0.3rem 0.75rem;color:#6e7681;border-bottom:1px solid #21262d">Description</th>
            <th style="text-align:left;padding:0.3rem 0.75rem;color:#6e7681;border-bottom:1px solid #21262d">Dates</th>
            <th style="text-align:left;padding:0.3rem 0.75rem;color:#6e7681;border-bottom:1px solid #21262d">References</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    detailRow.style.display = '';
    btn.textContent = '🔍 NVD ▲';
  } catch(err) {
    btn.textContent = '🔍 NVD';
    alert('NVD lookup failed: ' + err.message);
  } finally {
    btn.disabled = false;
  }
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

    document.getElementById('psirtDownloadLink').href     = `/psirt/download/${data.job_id}`;
    document.getElementById('psirtDownloadHtmlLink').href = `/psirt/html/${data.job_id}`;
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

// ── Unified Bulk Upload ───────────────────────────────────────────────────────
let unifiedRows    = [];
let unifiedHeaders = [];
let unifiedColMeta = {};   // {eox:[...], cov:[...], swim:[...], psirt:[...], bug:[...]}
let unifiedPage    = 1;

const unifiedDropZone     = document.getElementById('unifiedDropZone');
const unifiedFileInput    = document.getElementById('unifiedFileInput');
const unifiedUploadBtn    = document.getElementById('unifiedUploadBtn');
const unifiedUploadStatus = document.getElementById('unifiedUploadStatus');
const unifiedProgressWrap = document.getElementById('unifiedProgressWrap');
const unifiedProgressFill = document.getElementById('unifiedProgressFill');
const unifiedProgressText = document.getElementById('unifiedProgressText');

unifiedDropZone.addEventListener('click', () => unifiedFileInput.click());
unifiedDropZone.addEventListener('dragover', e => { e.preventDefault(); unifiedDropZone.classList.add('dragover'); });
unifiedDropZone.addEventListener('dragleave', () => unifiedDropZone.classList.remove('dragover'));
unifiedDropZone.addEventListener('drop', e => {
  e.preventDefault(); unifiedDropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) setUnifiedFile(e.dataTransfer.files[0]);
});
unifiedFileInput.addEventListener('change', () => { if (unifiedFileInput.files[0]) setUnifiedFile(unifiedFileInput.files[0]); });

function setUnifiedFile(f) {
  unifiedDropZone.querySelector('p').textContent = `Selected: ${f.name} (${(f.size/1024).toFixed(0)} KB)`;
  unifiedUploadBtn.disabled = false;
  unifiedUploadStatus.textContent = '';
  document.getElementById('unifiedDetectedCols').style.display = 'none';
}

document.getElementById('unifiedClearUploadBtn').addEventListener('click', () => {
  unifiedFileInput.value = '';
  unifiedDropZone.querySelector('p').textContent = 'Drag & drop your Excel file here, or click to browse';
  unifiedUploadBtn.disabled = true;
  unifiedUploadStatus.textContent = '';
  document.getElementById('unifiedDetectedCols').style.display    = 'none';
  document.getElementById('unifiedColMappingWrap').style.display  = 'none';
  document.getElementById('unifiedSummaryBar').style.display      = 'none';
  document.getElementById('unifiedDownloadBar').style.display     = 'none';
  document.getElementById('unifiedTableWrap').style.display       = 'none';
  unifiedProgressWrap.style.display = 'none';
  unifiedRows = []; unifiedHeaders = []; unifiedColMeta = {};
});

function setUnifiedProgress(pct, msg) {
  unifiedProgressWrap.style.display = 'block';
  unifiedProgressFill.style.width = pct + '%';
  unifiedProgressText.textContent = msg;
}

unifiedUploadBtn.addEventListener('click', () => doUnifiedUpload());

async function doUnifiedUpload(extraFields = {}) {
  const f = unifiedFileInput.files[0];
  if (!f) return;
  unifiedUploadBtn.disabled = true;
  unifiedUploadStatus.textContent = '';
  document.getElementById('unifiedColMappingWrap').style.display = 'none';
  setUnifiedProgress(10, 'Uploading file…');

  const fd = new FormData();
  fd.append('file', f);
  for (const [k, v] of Object.entries(extraFields)) fd.append(k, v);

  try {
    setUnifiedProgress(25, 'Running EOX + Coverage + SWIM + PSIRT lookups — this may take a moment…');
    const resp = await fetch('/unified/upload', { method: 'POST', body: fd });
    const data = await resp.json();

    if (data.needs_mapping && data.context === 'unified') {
      unifiedProgressWrap.style.display = 'none';
      const makeOpts = () => '<option value="">-- None --</option>' +
        data.available_columns.map(c => `<option value="${c.replace(/"/g,'&quot;')}">${c}</option>`).join('');
      document.getElementById('unifiedManualPidSel').innerHTML     = makeOpts();
      document.getElementById('unifiedManualSnSel').innerHTML      = makeOpts();
      document.getElementById('unifiedManualVersionSel').innerHTML = makeOpts();
      document.getElementById('unifiedManualOsTypeSel').innerHTML  = makeOpts();
      document.getElementById('unifiedColMappingWrap').style.display = 'block';
      return;
    }
    if (!resp.ok) {
      unifiedUploadStatus.textContent = 'Error: ' + (data.error || 'Unknown');
      unifiedProgressWrap.style.display = 'none';
      return;
    }

    setUnifiedProgress(100, `Done — ${data.stats.total} rows processed`);

    const dc = document.getElementById('unifiedDetectedCols');
    document.getElementById('unifiedColPid').textContent     = data.pid_col     ? `PID: "${data.pid_col}" · `      : '';
    document.getElementById('unifiedColSn').textContent      = data.sn_col      ? `SN: "${data.sn_col}" · `         : '';
    document.getElementById('unifiedColVersion').textContent = data.version_col ? `Version: "${data.version_col}" · ` : 'Version: none · ';
    document.getElementById('unifiedColOsType').textContent  = data.os_type_col ? `OS Type: "${data.os_type_col}"` : `OS Type: default (${data.default_os_type})`;
    dc.style.display = 'block';

    unifiedRows    = data.rows;
    unifiedHeaders = data.headers;
    unifiedColMeta = data.col_meta;
    unifiedPage    = 1;

    renderUnifiedSummary(data.stats);
    renderUnifiedTable();

    document.getElementById('unifiedDownloadLink').href     = `/unified/download/${data.job_id}`;
    document.getElementById('unifiedDownloadHtmlLink').href = `/unified/html/${data.job_id}`;
    document.getElementById('unifiedDownloadBar').style.display = 'block';

  } catch(err) {
    unifiedUploadStatus.textContent = 'Error: ' + err.message;
    unifiedProgressWrap.style.display = 'none';
  } finally {
    unifiedUploadBtn.disabled = false;
  }
}

function unifiedResubmitWithMapping() {
  const pidCol        = document.getElementById('unifiedManualPidSel').value;
  const snCol         = document.getElementById('unifiedManualSnSel').value;
  const versionCol    = document.getElementById('unifiedManualVersionSel').value;
  const osTypeCol     = document.getElementById('unifiedManualOsTypeSel').value;
  const defaultOsType = document.getElementById('unifiedDefaultOsTypeSel').value;
  if (!pidCol && !snCol) { unifiedUploadStatus.textContent = 'Select at least a PID or Serial Number column.'; return; }
  const extra = { default_os_type: defaultOsType };
  if (pidCol)     extra.pid_col      = pidCol;
  if (snCol)      extra.sn_col       = snCol;
  if (versionCol) extra.version_col  = versionCol;
  if (osTypeCol)  extra.os_type_col  = osTypeCol;
  doUnifiedUpload(extra);
}

function coverageStatusBadge(label) {
  if (!label) return '<span class="badge-sm badge-sm-uk">Unknown</span>';
  const l = label.toLowerCase();
  if (l === 'active')   return `<span class="badge-sm badge-sm-c">${label}</span>`;
  if (l === 'inactive') return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function renderUnifiedSummary(s) {
  const bar = document.getElementById('unifiedSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Total Rows</span>
    <span class="pill pill-c">${s.coverage_active} Coverage Active</span>
    <span class="pill pill-nc">${s.coverage_inactive} Inactive</span>
    <span class="pill pill-uk">${s.coverage_unknown} Unknown</span>
    <span class="pill pill-c">${s.psirt_compliant} PSIRT Compliant</span>
    <span class="pill pill-nc">${s.psirt_non_compliant} Non-Compliant</span>
    <span class="pill pill-uk">${s.psirt_na} NA</span>
    <span class="pill pill-c">${s.bug_compliant||0} Bug Compliant</span>
    <span class="pill pill-nc">${s.bug_non_compliant||0} Bug NC</span>
    <span class="pill pill-uk">${s.bug_na||0} Bug NA</span>
    <span class="pill" style="background:#f8514922;color:#f85149">${s.urgency_critical||0} Urgency Critical</span>
    <span class="pill" style="background:#d2992222;color:#d29922">${s.urgency_high||0} High</span>
    <span class="pill" style="background:#388bfd22;color:#388bfd">${s.urgency_medium||0} Medium</span>
    <span class="pill pill-c">${s.urgency_low||0} Low</span>`;
}

function urgencyBadge(level) {
  if (!level) return '<span class="badge-sm badge-sm-uk">—</span>';
  const l = level.toLowerCase();
  if (l === 'critical') return `<span class="badge-sm" style="background:#f851491a;color:#f85149">${level}</span>`;
  if (l === 'high')     return `<span class="badge-sm" style="background:#d299221a;color:#d29922">${level}</span>`;
  if (l === 'medium')   return `<span class="badge-sm" style="background:#388bfd1a;color:#388bfd">${level}</span>`;
  if (l === 'low')      return `<span class="badge-sm" style="background:#3fb9501a;color:#3fb950">${level}</span>`;
  return `<span class="badge-sm badge-sm-uk">${level}</span>`;
}

function renderUnifiedTable() {
  document.getElementById('unifiedTableWrap').style.display = 'block';
  const eoxCols     = unifiedColMeta.eox     || [];
  const covCols     = unifiedColMeta.cov     || [];
  const swimCols    = unifiedColMeta.swim    || [];
  const psirtCols   = unifiedColMeta.psirt   || [];
  const bugCols     = unifiedColMeta.bug     || [];
  const urgencyCols = unifiedColMeta.urgency || [];
  document.getElementById('unifiedThead').innerHTML =
    '<tr>' + unifiedHeaders.map(h => {
      const cls = eoxCols.includes(h)     ? 'eox-col'
                : covCols.includes(h)     ? 'cov-col'
                : swimCols.includes(h)    ? 'swim-col'
                : psirtCols.includes(h)   ? 'psirt-col'
                : bugCols.includes(h)     ? 'bug-col'
                : urgencyCols.includes(h) ? 'urgency-col' : '';
      return `<th class="${cls}">${h}</th>`;
    }).join('') + '</tr>';
  renderUnifiedPage(unifiedPage);
}

function renderUnifiedPage(page) {
  unifiedPage = page;
  const start = (page - 1) * PAGE_SIZE;
  const slice = unifiedRows.slice(start, start + PAGE_SIZE);
  const eoxCols     = unifiedColMeta.eox     || [];
  const covCols     = unifiedColMeta.cov     || [];
  const swimCols    = unifiedColMeta.swim    || [];
  const psirtCols   = unifiedColMeta.psirt   || [];
  const bugCols     = unifiedColMeta.bug     || [];
  const urgencyCols = unifiedColMeta.urgency || [];
  document.getElementById('unifiedTbody').innerHTML = slice.map(row =>
    '<tr>' + unifiedHeaders.map(h => {
      const v = row[h];
      const d = (v === null || v === undefined || v === '') ? '' : String(v);
      if (h === 'EOX Compliance')     return `<td>${eoxComplianceBadge(d)}</td>`;
      if (h === 'Coverage Status')    return `<td>${coverageStatusBadge(d)}</td>`;
      if (h === 'SWIM Compliance')    return `<td>${swimComplianceBadge(d)}</td>`;
      if (h === 'PSIRT Compliance')   return `<td>${psirtComplianceBadge(d)}</td>`;
      if (h === 'Bug Compliance')     return `<td>${bugComplianceBadge(d)}</td>`;
      if (h === 'Urgency Level')      return `<td>${urgencyBadge(d)}</td>`;
      if (h === 'Urgency Score')      return `<td class="mono" style="text-align:right">${d}</td>`;
      if (eoxCols.includes(h) || covCols.includes(h) || swimCols.includes(h)) {
        return `<td class="${!d?'na':'mono'}">${d||'N/A'}</td>`;
      }
      if (psirtCols.includes(h) || bugCols.includes(h) || urgencyCols.includes(h)) {
        return `<td class="${!d?'na':'mono'}" title="${d.replace(/"/g,'&quot;')}">${d||'N/A'}</td>`;
      }
      return `<td title="${d.replace(/"/g,'&quot;')}">${d}</td>`;
    }).join('') + '</tr>'
  ).join('');
  renderUnifiedPagination();
}

function eoxComplianceBadge(label) {
  if (!label) return '<span class="badge-sm badge-sm-uk">Unknown</span>';
  const l = label.toLowerCase();
  if (l.includes('compliant') && !l.includes('non')) return `<span class="badge-sm badge-sm-c">${label}</span>`;
  if (l.includes('non-compliant') || l.includes('noncompliant')) return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  if (l.includes('warning')) return `<span class="badge-sm badge-sm-w">${label}</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function renderUnifiedPagination() {
  const total = unifiedRows.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const pg = document.getElementById('unifiedPagination');
  if (pages <= 1) { pg.innerHTML = ''; return; }
  let html = `<span class="page-info-txt">Rows ${(unifiedPage-1)*PAGE_SIZE+1}–${Math.min(unifiedPage*PAGE_SIZE,total)} of ${total}</span>`;
  if (unifiedPage > 1) html += `<button class="page-btn" onclick="renderUnifiedPage(${unifiedPage-1})">‹ Prev</button>`;
  const us = Math.max(1, unifiedPage-3), ue = Math.min(pages, unifiedPage+3);
  for (let i = us; i <= ue; i++)
    html += `<button class="page-btn${i===unifiedPage?' active':''}" onclick="renderUnifiedPage(${i})">${i}</button>`;
  if (unifiedPage < pages) html += `<button class="page-btn" onclick="renderUnifiedPage(${unifiedPage+1})">Next ›</button>`;
  pg.innerHTML = html;
}

// ── Saved Device Lists ────────────────────────────────────────────────────────
// Each tab stores its current rows/headers in these module-level vars so Save works globally.
// EOX bulk: bulkRows / bulkHeaders (already defined above)
// Others reuse their own rows vars.

async function loadSavedLists() {
  try {
    const resp = await fetch('/lists');
    const lists = await resp.json();
    renderSavedLists(lists);
  } catch(e) { /* silent */ }
}

function renderSavedLists(lists) {
  const wrap = document.getElementById('savedListsWrap');
  if (!lists.length) {
    wrap.innerHTML = '<p style="color:#6e7681;font-size:0.85rem">No saved lists yet. After processing a file, click <strong>💾 Save List</strong> to save it for quick reload.</p>';
    return;
  }
  wrap.innerHTML = lists.map(l => {
    const date = new Date(l.created_at * 1000).toLocaleString();
    return `<div style="display:flex;align-items:center;gap:0.75rem;padding:0.5rem 0;border-bottom:1px solid #21262d">
      <span style="flex:1;color:#c9d1d9;font-size:0.85rem">${l.name}</span>
      <span style="color:#6e7681;font-size:0.75rem">${l.rows.length} rows · ${date}</span>
      <button class="btn-secondary" style="padding:0.2rem 0.6rem;font-size:0.75rem"
        onclick="loadSavedListIntoTab('${l.list_id}')">Load</button>
      <button class="btn-secondary" style="padding:0.2rem 0.6rem;font-size:0.75rem;color:#f85149"
        onclick="deleteSavedList('${l.list_id}')">✕</button>
    </div>`;
  }).join('');
}

async function saveCurrentList(tabType) {
  let rows, headers;
  if (tabType === 'eox')    { rows = bulkRows;    headers = bulkHeaders; }
  else if (tabType === 'swim')   { rows = swimRows;    headers = swimHeaders; }
  else if (tabType === 'psirt')  { rows = psirtRows;   headers = psirtHeaders; }
  else if (tabType === 'unified'){ rows = unifiedRows; headers = unifiedHeaders; }
  else if (tabType === 'bug')    { rows = bugRows;     headers = bugHeaders; }
  if (!rows || !rows.length) { alert('No data to save.'); return; }
  const name = prompt('Save list as:');
  if (!name) return;
  const resp = await fetch('/lists/save', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name, columns: headers, rows}),
  });
  const data = await resp.json();
  if (data.error) { alert('Error: ' + data.error); return; }
  loadSavedLists();
}

async function deleteSavedList(listId) {
  if (!confirm('Delete this saved list?')) return;
  await fetch(`/lists/${listId}`, {method: 'DELETE'});
  loadSavedLists();
}

function loadSavedListIntoTab(listId) {
  // Navigate to the bulk tab and display the saved list data
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector('.tab-btn[data-tab="bulk"]').classList.add('active');
  document.getElementById('tab-bulk').classList.add('active');

  fetch('/lists').then(r => r.json()).then(lists => {
    const list = lists.find(l => l.list_id === listId);
    if (!list) return;
    bulkRows    = list.rows;
    bulkHeaders = list.columns;
    eoxColNames = [];
    currentPage = 1;
    renderBulkTable();
    document.getElementById('bulkSummaryBar').style.display = 'none';
    document.getElementById('bulkDownloadBar').style.display = 'none';
    document.getElementById('bulkTableWrap').style.display = 'block';
  });
}

// Load saved lists on page load
loadSavedLists();

// ── Compliance Dashboard ──────────────────────────────────────────────────────
let _dashCharts = {};

document.querySelector('.tab-btn[data-tab="dashboard"]').addEventListener('click', () => {
  loadDashboard();
  loadEmailConfig();
});

async function loadDashboard() {
  try {
    const resp = await fetch('/dashboard/data');
    const jobs = await resp.json();
    renderDashboard(jobs);
  } catch(e) {
    document.getElementById('dashboardEmpty').textContent = 'Failed to load dashboard data.';
  }
}

async function loadEmailConfig() {
  try {
    const cfg = await (await fetch('/settings/email-config')).json();
    const el = document.getElementById('emailConfigDisplay');
    if (cfg.configured) {
      el.innerHTML = `
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem">
          <span class="pill pill-c">Configured</span>
          <span class="pill pill-total">Host: ${cfg.smtp_host}:${cfg.smtp_port}</span>
          <span class="pill pill-total">From: ${cfg.alert_from||'(not set)'}</span>
          <span class="pill pill-total">To: ${cfg.alert_to}</span>
          <span class="pill pill-total">Min NC: ${cfg.min_noncompliant}</span>
        </div>`;
    } else {
      el.innerHTML = '<span class="pill pill-uk">Not configured — set SMTP_HOST and ALERT_EMAIL_TO env vars</span>';
    }
  } catch(e) { /* silent */ }
}

async function sendTestEmail() {
  const statusEl = document.getElementById('emailTestStatus');
  statusEl.textContent = 'Sending…';
  try {
    const resp = await fetch('/settings/test-email', { method: 'POST' });
    const data = await resp.json();
    statusEl.textContent = data.ok
      ? `✓ Test email sent to ${data.sent_to}`
      : `✗ ${data.error}`;
  } catch(e) {
    statusEl.textContent = 'Error: ' + e.message;
  }
}

function renderDashboard(jobs) {
  const empty = document.getElementById('dashboardEmpty');
  const charts = document.getElementById('dashboardCharts');
  if (!jobs.length) { empty.style.display = 'block'; charts.style.display = 'none'; return; }
  empty.style.display = 'none';
  charts.style.display = 'block';

  // Aggregate EOX compliance
  let eoxC = 0, eoxW = 0, eoxNC = 0, eoxU = 0;
  // Aggregate PSIRT compliance
  let psirtC = 0, psirtNC = 0, psirtNA = 0;
  // Aggregate Coverage
  let covA = 0, covI = 0, covU = 0;
  // Aggregate Bug compliance
  let bugC = 0, bugNC = 0, bugNA = 0;
  // Aggregate Urgency distribution
  let urgCrit = 0, urgHigh = 0, urgMed = 0, urgLow = 0;

  const trend = jobs.slice(0, 30).reverse().map(j => ({
    label: `${j.job_type.toUpperCase()} ${new Date(j.created_at*1000).toLocaleDateString()}`,
    total: j.stats.total || 0,
    type: j.job_type,
  }));

  for (const j of jobs) {
    const s = j.stats;
    if (j.job_type === 'eox' || j.job_type === 'unified') {
      eoxC  += (s.compliant     || 0);
      eoxW  += (s.warning       || 0);
      eoxNC += (s.noncompliant  || s.non_compliant || 0);
      eoxU  += (s.unknown       || 0);
    }
    if (j.job_type === 'psirt' || j.job_type === 'unified') {
      psirtC  += (s.compliant       || s.psirt_compliant    || 0);
      psirtNC += (s.non_compliant   || s.psirt_non_compliant|| 0);
      psirtNA += (s.na              || s.psirt_na           || 0);
    }
    if (j.job_type === 'unified') {
      covA += (s.coverage_active   || 0);
      covI += (s.coverage_inactive || 0);
      covU += (s.coverage_unknown  || 0);
    }
    if (j.job_type === 'bug' || j.job_type === 'unified') {
      bugC  += (s.compliant        || s.bug_compliant     || 0);
      bugNC += (s.non_compliant    || s.bug_non_compliant || 0);
      bugNA += (s.na               || s.bug_na            || 0);
    }
    if (j.job_type === 'unified') {
      urgCrit += (s.urgency_critical || 0);
      urgHigh += (s.urgency_high     || 0);
      urgMed  += (s.urgency_medium   || 0);
      urgLow  += (s.urgency_low      || 0);
    }
  }

  const donutOpts = (labels, data, colors) => ({
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 1, borderColor: '#0d1117' }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#8b949e', font: { size: 11 } } }
      }
    }
  });

  const rebuildChart = (id, cfg) => {
    if (_dashCharts[id]) _dashCharts[id].destroy();
    _dashCharts[id] = new Chart(document.getElementById(id), cfg);
  };

  rebuildChart('dashEoxDonut', donutOpts(
    ['Compliant', 'Warning', 'Non-Compliant', 'Unknown'],
    [eoxC, eoxW, eoxNC, eoxU],
    ['#3fb950', '#e3b341', '#f85149', '#6e7681']
  ));

  rebuildChart('dashPsirtDonut', donutOpts(
    ['Compliant', 'Non-Compliant', 'NA'],
    [psirtC, psirtNC, psirtNA],
    ['#3fb950', '#f85149', '#6e7681']
  ));

  rebuildChart('dashCovDonut', donutOpts(
    ['Active', 'Inactive', 'Unknown'],
    [covA, covI, covU],
    ['#3fb950', '#f85149', '#6e7681']
  ));

  rebuildChart('dashBugDonut', donutOpts(
    ['Compliant', 'Non-Compliant', 'NA'],
    [bugC, bugNC, bugNA],
    ['#3fb950', '#f85149', '#6e7681']
  ));

  rebuildChart('dashUrgencyDonut', donutOpts(
    ['Critical', 'High', 'Medium', 'Low'],
    [urgCrit, urgHigh, urgMed, urgLow],
    ['#f85149', '#d29922', '#388bfd', '#3fb950']
  ));

  const typeColor = t => t === 'eox' ? '#58a6ff' : t === 'psirt' ? '#f85149' : t === 'swim' ? '#e3b341' : t === 'bug' ? '#a371f7' : '#3fb950';
  rebuildChart('dashTrendBar', {
    type: 'bar',
    data: {
      labels: trend.map(t => t.label),
      datasets: [{
        label: 'Rows processed',
        data: trend.map(t => t.total),
        backgroundColor: trend.map(t => typeColor(t.type)),
        borderRadius: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#6e7681', maxRotation: 45, font: { size: 10 } }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#6e7681' }, grid: { color: '#21262d' }, beginAtZero: true }
      },
      plugins: { legend: { display: false } }
    }
  });

  // Non-compliant trend line chart
  const NC_TYPES   = ['eox', 'psirt', 'bug', 'unified'];
  const NC_COLORS  = { eox: '#58a6ff', psirt: '#f85149', bug: '#a371f7', unified: '#3fb950' };
  const NC_NC_KEY  = { eox: 'non_compliant', psirt: 'psirt_non_compliant', bug: 'bug_non_compliant', unified: 'non_compliant' };
  const ncJobs     = [...jobs].reverse().filter(j => NC_TYPES.includes(j.job_type));
  const ncLabels   = ncJobs.map(j => new Date(j.created_at * 1000).toLocaleDateString());
  const ncDatasets = NC_TYPES.map(type => {
    const color = NC_COLORS[type];
    const key   = NC_NC_KEY[type];
    return {
      label:           type.toUpperCase(),
      data:            ncJobs.map(j => j.job_type === type ? (j.stats[key] || j.stats.noncompliant || 0) : null),
      borderColor:     color,
      backgroundColor: color + '33',
      pointRadius:     4,
      spanGaps:        false,
      tension:         0.3,
      fill:            false,
    };
  }).filter((_, i) => ncJobs.some(j => j.job_type === NC_TYPES[i]));

  rebuildChart('dashNcTrend', {
    type: 'line',
    data: { labels: ncLabels, datasets: ncDatasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#6e7681', maxRotation: 45, font: { size: 10 } }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#6e7681' }, grid: { color: '#21262d' }, beginAtZero: true,
             title: { display: true, text: 'Non-Compliant Devices', color: '#6e7681' } }
      },
      plugins: { legend: { labels: { color: '#8b949e', boxWidth: 12 } },
                 tooltip: { callbacks: { label: ctx => `${ctx.dataset.label}: ${ctx.parsed.y} non-compliant` } } }
    }
  });

  // Job history table
  const TYPE_COLOR = { eox: '#58a6ff', swim: '#e3b341', psirt: '#f85149', unified: '#3fb950', bug: '#a371f7' };
  document.getElementById('dashJobTable').innerHTML = `
    <h3 style="font-size:0.9rem;color:#8b949e;margin-bottom:0.75rem">Recent Jobs</h3>
    <table style="width:100%;border-collapse:collapse;font-size:0.78rem">
      <thead><tr>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Job ID</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Type</th>
        <th style="text-align:left;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Date</th>
        <th style="text-align:right;padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Rows</th>
      </tr></thead>
      <tbody>
        ${jobs.slice(0, 20).map(j => `<tr style="border-bottom:1px solid #21262d">
          <td style="padding:0.4rem 0.6rem;font-family:monospace;color:#8b949e">${j.job_id}</td>
          <td style="padding:0.4rem 0.6rem"><span style="background:${TYPE_COLOR[j.job_type]||'#555'}22;color:${TYPE_COLOR[j.job_type]||'#aaa'};padding:0.15rem 0.5rem;border-radius:3px;font-size:0.75rem">${j.job_type.toUpperCase()}</span></td>
          <td style="padding:0.4rem 0.6rem;color:#8b949e">${new Date(j.created_at*1000).toLocaleString()}</td>
          <td style="padding:0.4rem 0.6rem;text-align:right;color:#c9d1d9">${j.stats.total||0}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
}

// ── CMDB Import (NetBox / ServiceNow) ────────────────────────────────────────
function toggleImportSection(source) {
  const sections = {netbox: 'importNetboxForm', servicenow: 'importSnowForm'};
  Object.entries(sections).forEach(([k, id]) => {
    document.getElementById(id).style.display = (k === source)
      ? (document.getElementById(id).style.display === 'none' ? 'block' : 'none')
      : 'none';
  });
}

async function runImport(source) {
  const statusEl = source === 'netbox'
    ? document.getElementById('nbStatus')
    : document.getElementById('snowStatus');
  statusEl.textContent = 'Fetching…';

  let body;
  if (source === 'netbox') {
    body = {
      url:   document.getElementById('nbUrl').value.trim(),
      token: document.getElementById('nbToken').value.trim(),
      limit: parseInt(document.getElementById('nbLimit').value) || 200,
    };
  } else {
    body = {
      url:      document.getElementById('snowUrl').value.trim(),
      username: document.getElementById('snowUser').value.trim(),
      password: document.getElementById('snowPass').value.trim(),
      table:    document.getElementById('snowTable').value.trim() || 'cmdb_ci_ip_switch',
      limit:    parseInt(document.getElementById('snowLimit').value) || 200,
    };
  }

  try {
    const resp = await fetch(`/import/${source}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (data.error) { statusEl.textContent = 'Error: ' + data.error; return; }

    statusEl.textContent = `${data.count} devices fetched — loading into Unified Report…`;

    // Build CSV from device list
    const devices = data.devices;
    if (!devices.length) { statusEl.textContent = 'No devices returned.'; return; }
    const cols   = Object.keys(devices[0]);
    const csvRows = [cols.join(','), ...devices.map(d =>
      cols.map(c => JSON.stringify(d[c] ?? '')).join(',')
    )];
    const csvBlob = new Blob([csvRows.join('\n')], {type: 'text/csv'});
    const file    = new File([csvBlob], `${source}_devices.csv`, {type: 'text/csv'});

    // Inject into the unified file input and trigger upload
    const dt = new DataTransfer();
    dt.items.add(file);
    const inp = document.getElementById('unifiedFileInput');
    inp.files = dt.files;
    inp.dispatchEvent(new Event('change'));

    // Scroll to top of unified tab
    document.getElementById('tab-unified').scrollIntoView({behavior: 'smooth'});
    statusEl.textContent = `✓ ${data.count} devices loaded — click Process File.`;
  } catch(err) {
    statusEl.textContent = 'Error: ' + err.message;
  }
}

// ── Bugs Tab ──────────────────────────────────────────────────────────────────
let bugRows    = [];
let bugHeaders = [];
let bugCols    = [];
let bugPage    = 1;

// Single search
document.getElementById('bugSearchForm').addEventListener('submit', async e => {
  e.preventDefault();
  const pid     = document.getElementById('bugPid').value.trim();
  const version = document.getElementById('bugVersion').value.trim();
  const status  = document.getElementById('bugSearchStatus');
  const btn     = document.getElementById('bugSearchBtn');
  if (!pid) { status.textContent = 'Enter a Product ID.'; return; }
  btn.disabled = true;
  status.textContent = '';
  document.getElementById('bugResults').innerHTML = '<div class="loading"><span class="spinner"></span>Querying Cisco Bug API…</div>';
  try {
    const resp = await fetch('/bug/search', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pid, version}),
    });
    const data = await resp.json();
    if (!resp.ok) { document.getElementById('bugResults').innerHTML = `<div class="error-msg">Error: ${data.error || 'Unknown'}</div>`; return; }
    renderBugResults(data.result);
  } catch(err) {
    document.getElementById('bugResults').innerHTML = `<div class="error-msg">Network error: ${err.message}</div>`;
  } finally { btn.disabled = false; }
});

document.getElementById('bugClearBtn').addEventListener('click', () => {
  document.getElementById('bugPid').value = '';
  document.getElementById('bugVersion').value = '';
  document.getElementById('bugResults').innerHTML = '';
  document.getElementById('bugSearchStatus').textContent = '';
});

function bugSeverityBadge(sev) {
  const n = parseInt(sev, 10);
  if (n === 1) return `<span class="badge-sm badge-sm-nc">Critical</span>`;
  if (n === 2) return `<span class="badge-sm" style="background:rgba(227,100,0,.15);color:#e37300;border:1px solid rgba(227,100,0,.3)">High</span>`;
  if (n === 3) return `<span class="badge-sm badge-sm-uk">Moderate</span>`;
  if (n === 4) return `<span class="badge-sm badge-sm-uk">Minor</span>`;
  return `<span class="badge-sm badge-sm-uk">${sev||'?'}</span>`;
}

function bugStatusBadge(status) {
  const labels = {O:'Open',F:'Fixed',T:'Terminated',E:'Unreproducible',D:'Duplicate'};
  const label = labels[status] || status || '?';
  if (status === 'O') return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  if (status === 'F') return `<span class="badge-sm badge-sm-c">${label}</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function bugComplianceBadge(label) {
  if (!label) return '<span class="badge-sm badge-sm-uk">Unknown</span>';
  const l = label.toLowerCase();
  if (l === 'compliant')     return `<span class="badge-sm badge-sm-c">${label}</span>`;
  if (l === 'non-compliant') return `<span class="badge-sm badge-sm-nc">${label}</span>`;
  if (l === 'na')            return `<span class="badge-sm badge-sm-uk">NA</span>`;
  return `<span class="badge-sm badge-sm-uk">${label}</span>`;
}

function renderBugResults(result) {
  const div = document.getElementById('bugResults');
  if (result.error) { div.innerHTML = `<div class="error-msg">Error: ${result.error}</div>`; return; }
  const bugs = result.bugs || [];
  const openBugs = bugs.filter(b => b.status === 'O');
  let html = `<div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <div>
        <span style="font-family:monospace;color:#a371f7;font-size:1rem;font-weight:700">${result.pid}</span>
        ${result.version ? `<span style="color:#6e7681;font-size:0.85rem;margin-left:0.5rem">v${result.version}</span>` : ''}
      </div>
      <div style="display:flex;gap:0.75rem;align-items:center">
        ${bugComplianceBadge(result.compliance)}
        <span style="font-size:0.8rem;color:#6e7681">${bugs.length} bugs · ${openBugs.length} open</span>
      </div>
    </div>`;
  if (bugs.length) {
    html += `<div class="table-wrap" style="margin:0"><table style="width:100%;border-collapse:collapse;font-size:0.78rem">
      <thead><tr>
        <th style="padding:0.4rem 0.6rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap">Severity</th>
        <th style="padding:0.4rem 0.6rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d">Bug ID</th>
        <th style="padding:0.4rem 0.6rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d">Headline</th>
        <th style="padding:0.4rem 0.6rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d;white-space:nowrap">Status</th>
        <th style="padding:0.4rem 0.6rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d">Affected</th>
        <th style="padding:0.4rem 0.6rem;text-align:left;color:#8b949e;border-bottom:1px solid #30363d">Fixed In</th>
      </tr></thead><tbody>`;
    for (const b of bugs) {
      const bugUrl = `https://bst.cloudapps.cisco.com/bugsearch/bug/${b.bug_id}`;
      html += `<tr style="border-bottom:1px solid #21262d">
        <td style="padding:0.4rem 0.6rem">${bugSeverityBadge(b.severity)}</td>
        <td style="padding:0.4rem 0.6rem;font-family:monospace"><a href="${bugUrl}" target="_blank" style="color:#a371f7;text-decoration:none">${b.bug_id}</a></td>
        <td style="padding:0.4rem 0.6rem;max-width:400px;overflow:hidden;text-overflow:ellipsis" title="${(b.headline||'').replace(/"/g,'&quot;')}">${b.headline||''}</td>
        <td style="padding:0.4rem 0.6rem">${bugStatusBadge(b.status)}</td>
        <td style="padding:0.4rem 0.6rem;font-family:monospace;font-size:0.72rem;max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${(b.known_affected_releases||'').replace(/"/g,'&quot;')}">${b.known_affected_releases||'—'}</td>
        <td style="padding:0.4rem 0.6rem;font-family:monospace;font-size:0.72rem;max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${(b.known_fixed_releases||'').replace(/"/g,'&quot;')}">${b.known_fixed_releases||'—'}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  } else {
    html += '<p style="color:#3fb950;padding:1rem 0">No bugs found — device is Compliant.</p>';
  }
  html += '</div>';
  div.innerHTML = html;
}

// Bulk upload
let _bugFile = null;
let _bugAvailCols = [];

const bugDropZone  = document.getElementById('bugDropZone');
const bugFileInput = document.getElementById('bugFileInput');
const bugUploadBtn = document.getElementById('bugUploadBtn');

bugDropZone.addEventListener('click', () => bugFileInput.click());
bugDropZone.addEventListener('dragover', e => { e.preventDefault(); bugDropZone.classList.add('dragover'); });
bugDropZone.addEventListener('dragleave', () => bugDropZone.classList.remove('dragover'));
bugDropZone.addEventListener('drop', e => { e.preventDefault(); bugDropZone.classList.remove('dragover'); if (e.dataTransfer.files[0]) { bugFileInput.files = e.dataTransfer.files; onBugFile(e.dataTransfer.files[0]); } });
bugFileInput.addEventListener('change', () => { if (bugFileInput.files[0]) onBugFile(bugFileInput.files[0]); });

function onBugFile(file) {
  _bugFile = file;
  bugUploadBtn.disabled = false;
  document.getElementById('bugUploadStatus').textContent = file.name;
}

document.getElementById('bugClearUploadBtn').addEventListener('click', () => {
  _bugFile = null; bugUploadBtn.disabled = true;
  bugFileInput.value = '';
  document.getElementById('bugUploadStatus').textContent = '';
  document.getElementById('bugDetectedCols').style.display = 'none';
  document.getElementById('bugColMappingWrap').style.display = 'none';
  document.getElementById('bugProgressWrap').style.display = 'none';
  document.getElementById('bugSummaryBar').style.display = 'none';
  document.getElementById('bugDownloadBar').style.display = 'none';
  document.getElementById('bugTableWrap').style.display = 'none';
  bugRows = []; bugHeaders = []; bugCols = [];
});

bugUploadBtn.addEventListener('click', () => doBugUpload({}));

async function doBugUpload(extraFields) {
  if (!_bugFile) return;
  const pw = document.getElementById('bugProgressWrap');
  const pf = document.getElementById('bugProgressFill');
  const pt = document.getElementById('bugProgressText');
  pw.style.display = 'block'; pf.style.width = '30%'; pt.textContent = 'Uploading…';
  bugUploadBtn.disabled = true;
  const fd = new FormData();
  fd.append('file', _bugFile);
  for (const [k, v] of Object.entries(extraFields)) fd.append(k, v);
  try {
    pf.style.width = '60%'; pt.textContent = 'Querying Bug API…';
    const resp = await fetch('/bug/upload', { method: 'POST', body: fd });
    const data = await resp.json();
    pf.style.width = '100%';
    if (!resp.ok) { pt.textContent = 'Error: ' + (data.error || 'Unknown'); bugUploadBtn.disabled = false; return; }
    if (data.needs_mapping) {
      pt.textContent = 'Column mapping required.';
      _bugAvailCols = data.available_columns || [];
      const pidSel = document.getElementById('bugManualPidSel');
      const verSel = document.getElementById('bugManualVersionSel');
      pidSel.innerHTML = _bugAvailCols.map(c => `<option value="${c}">${c}</option>`).join('');
      verSel.innerHTML = '<option value="">(none)</option>' + _bugAvailCols.map(c => `<option value="${c}">${c}</option>`).join('');
      document.getElementById('bugColMappingWrap').style.display = 'block';
      bugUploadBtn.disabled = false;
      return;
    }
    pw.style.display = 'none';
    document.getElementById('bugColMappingWrap').style.display = 'none';
    if (data.pid_col) {
      document.getElementById('bugDetectedCols').style.display = 'block';
      document.getElementById('bugColPid').textContent = data.pid_col || '';
      document.getElementById('bugColVersion').textContent = data.version_col || '';
    }
    bugRows = data.rows || [];
    bugHeaders = data.headers || [];
    bugCols = data.bug_col_names || [];
    bugPage = 1;
    renderBugSummary(data.stats);
    renderBugTable();
    document.getElementById('bugDownloadLink').href     = `/bug/download/${data.job_id}`;
    document.getElementById('bugDownloadHtmlLink').href = `/bug/html/${data.job_id}`;
    document.getElementById('bugDownloadBar').style.display = 'block';
  } catch(err) {
    pt.textContent = 'Network error: ' + err.message;
  } finally { bugUploadBtn.disabled = false; }
}

function bugResubmitWithMapping() {
  const pid_col     = document.getElementById('bugManualPidSel').value;
  const version_col = document.getElementById('bugManualVersionSel').value;
  doBugUpload({pid_col, version_col});
}

function renderBugSummary(s) {
  const bar = document.getElementById('bugSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Total Rows</span>
    <span class="pill pill-total">${s.unique_pids} Unique PIDs</span>
    <span class="pill pill-c">${s.compliant} Compliant</span>
    <span class="pill pill-nc">${s.non_compliant} Non-Compliant</span>
    <span class="pill pill-uk">${s.na} NA</span>`;
}

function renderBugTable() {
  document.getElementById('bugTableWrap').style.display = 'block';
  document.getElementById('bugThead').innerHTML =
    '<tr>' + bugHeaders.map(h => {
      const cls = bugCols.includes(h) ? 'bug-col' : '';
      return `<th class="${cls}">${h}</th>`;
    }).join('') + '</tr>';
  renderBugPage(bugPage);
}

function renderBugPage(page) {
  bugPage = page;
  const start = (page - 1) * PAGE_SIZE;
  const slice = bugRows.slice(start, start + PAGE_SIZE);
  document.getElementById('bugTbody').innerHTML = slice.map(row =>
    '<tr>' + bugHeaders.map(h => {
      const v = row[h];
      const d = (v === null || v === undefined || v === '') ? '' : String(v);
      if (h === 'Bug Compliance') return `<td>${bugComplianceBadge(d)}</td>`;
      if (bugCols.includes(h)) return `<td class="${!d?'na':'mono'}" title="${d.replace(/"/g,'&quot;')}">${d||'N/A'}</td>`;
      return `<td title="${d.replace(/"/g,'&quot;')}">${d}</td>`;
    }).join('') + '</tr>'
  ).join('');
  renderBugPagination();
}

function renderBugPagination() {
  const total = bugRows.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const pg = document.getElementById('bugPagination');
  if (pages <= 1) { pg.innerHTML = ''; return; }
  let html = `<span class="page-info-txt">Rows ${(bugPage-1)*PAGE_SIZE+1}–${Math.min(bugPage*PAGE_SIZE,total)} of ${total}</span>`;
  if (bugPage > 1) html += `<button class="page-btn" onclick="renderBugPage(${bugPage-1})">‹ Prev</button>`;
  const bs = Math.max(1, bugPage-3), be = Math.min(pages, bugPage+3);
  for (let i = bs; i <= be; i++)
    html += `<button class="page-btn${i===bugPage?' active':''}" onclick="renderBugPage(${i})">${i}</button>`;
  if (bugPage < pages) html += `<button class="page-btn" onclick="renderBugPage(${bugPage+1})">Next ›</button>`;
  pg.innerHTML = html;
}

// Trigger dashboard reload when Bugs tab is clicked
document.querySelector('.tab-btn[data-tab="bugs"]').addEventListener('click', () => { /* standalone tab, no auto-load */ });

// ── Config Diff Risk Analyzer ─────────────────────────────────────────────────
let _diffResult = null;

// File loaders
document.getElementById('refConfigFile').addEventListener('change', e => {
  const f = e.target.files[0]; if (!f) return;
  document.getElementById('refFileName').textContent = f.name;
  f.text().then(t => document.getElementById('refConfig').value = t);
});
document.getElementById('curConfigFile').addEventListener('change', e => {
  const f = e.target.files[0]; if (!f) return;
  document.getElementById('curFileName').textContent = f.name;
  f.text().then(t => document.getElementById('curConfig').value = t);
});

function loadDiffSample(side) {
  const refSample = `version 16.12
hostname BRANCH-SW1
!
aaa authentication login default local
service password-encryption
!
interface GigabitEthernet1/0/1
 description Uplink to Core
 no shutdown
 ip address 10.1.1.1 255.255.255.0
!
interface GigabitEthernet1/0/13
!
ip access-list extended MGMT-IN
 permit tcp 10.0.0.0 0.0.0.255 any eq 22
 deny   ip any any log
!
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
!
spanning-tree mode rapid-pvst
ntp server 10.0.0.1
logging host 10.0.0.2
`;
  const curSample = `version 16.12
hostname BRANCH-SW1
!
service password-encryption
!
interface GigabitEthernet1/0/1
 description Uplink to Core
 no shutdown
 ip address 10.1.1.2 255.255.255.0
!
interface GigabitEthernet1/0/13
 description Triggering Compliance Check
!
no ip access-list extended MGMT-IN
ip access-list extended MGMT-IN
 permit ip any any
!
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
!
spanning-tree mode rapid-pvst
ntp server 10.0.0.1
`;
  if (side === 'ref') document.getElementById('refConfig').value = refSample.trim();
  else                document.getElementById('curConfig').value = curSample.trim();
}

function clearDiff() {
  document.getElementById('refConfig').value = '';
  document.getElementById('curConfig').value = '';
  document.getElementById('refFileName').textContent = '';
  document.getElementById('curFileName').textContent = '';
  document.getElementById('diffStatus').textContent = '';
  document.getElementById('diffSummaryBar').style.display = 'none';
  document.getElementById('diffDownloadBar').style.display = 'none';
  document.getElementById('diffResultWrap').style.display = 'none';
  document.getElementById('diffExplainWrap').style.display = 'none';
  _diffResult = null;
}

document.getElementById('diffAnalyzeBtn').addEventListener('click', async () => {
  const ref = document.getElementById('refConfig').value.trim();
  const cur = document.getElementById('curConfig').value.trim();
  const status = document.getElementById('diffStatus');
  if (!ref || !cur) { status.textContent = 'Paste or upload both configs first.'; return; }

  const btn = document.getElementById('diffAnalyzeBtn');
  btn.disabled = true;
  status.textContent = 'Analyzing…';

  try {
    const resp = await fetch('/config-diff/analyze', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        reference: ref,
        current:   cur,
        min_risk:  document.getElementById('diffMinRisk').value,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) { status.textContent = 'Error: ' + (data.error || 'Unknown'); return; }
    _diffResult = data;
    status.textContent = '';
    renderDiffResult(data);
  } catch(err) {
    status.textContent = 'Network error: ' + err.message;
  } finally { btn.disabled = false; }
});

function riskRowClass(level, action) {
  if (action === 'separator') return 'diff-sep';
  if (action === 'context')   return 'diff-context';
  if (level === 'critical')   return 'diff-add risk-critical';
  if (level === 'high')       return 'diff-add risk-high';
  if (level === 'medium')     return action === 'remove' ? 'diff-remove risk-medium' : 'diff-add risk-medium';
  if (level === 'low')        return action === 'remove' ? 'diff-remove risk-low' : 'diff-add risk-low';
  return action === 'add' ? 'diff-add' : action === 'remove' ? 'diff-remove' : '';
}

function riskBadgeHtml(level, reason) {
  if (!reason) return '';
  const cls = {critical:'rb-critical', high:'rb-high', medium:'rb-medium', low:'rb-low'}[level] || '';
  const label = {critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW'}[level] || '';
  return `<span class="risk-badge ${cls}">${label}</span><span class="risk-reason">${reason}</span>`;
}

function scoreBadgeClass(score) {
  if (score >= 20) return 'score-critical';
  if (score >= 10) return 'score-high';
  if (score >= 3)  return 'score-medium';
  return 'score-ok';
}

function renderDiffResult(data) {
  const s = data.summary;
  const score = data.risk_score;

  // Summary bar
  const bar = document.getElementById('diffSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="score-badge ${scoreBadgeClass(score)}">Risk Score: ${score}</span>
    <span class="pill pill-total">${s.total_changes} Changes (+${s.lines_added} / -${s.lines_removed})</span>
    ${s.critical ? `<span class="pill pill-nc">${s.critical} Critical</span>` : ''}
    ${s.high     ? `<span class="pill" style="background:rgba(227,130,0,.1);color:#e37300;border:1px solid rgba(227,130,0,.3)">${s.high} High</span>` : ''}
    ${s.medium   ? `<span class="pill pill-w">${s.medium} Medium</span>` : ''}
    ${s.low      ? `<span class="pill pill-uk">${s.low} Low</span>` : ''}
    ${!s.critical && !s.high && !s.medium && !s.low ? '<span class="pill pill-c">No Risk Patterns Detected</span>' : ''}`;

  // Table
  const tbody = document.getElementById('diffTbody');
  document.getElementById('diffThead').innerHTML = `<tr>
    <th style="padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;width:3.5rem;text-align:right">Ref#</th>
    <th style="padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;width:3.5rem;text-align:right">Cur#</th>
    <th style="padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d;width:1.2rem"></th>
    <th style="padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Config Line</th>
    <th style="padding:0.4rem 0.6rem;color:#8b949e;border-bottom:1px solid #30363d">Risk</th>
  </tr>`;

  let rows = '';
  for (const c of data.changes) {
    const rowCls = riskRowClass(c.risk_level, c.action);
    const prefix = c.action === 'add' ? '+' : c.action === 'remove' ? '−' : c.action === 'separator' ? '⋯' : ' ';
    const prefixColor = c.action === 'add' ? '#3fb950' : c.action === 'remove' ? '#f85149' : '#484f58';
    const content = c.content.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const refNo = c.ref_line_no || '';
    const curNo = c.cur_line_no || '';

    if (c.action === 'separator') {
      rows += `<tr class="${rowCls}"><td colspan="5" style="padding:0.25rem 0.75rem;text-align:center;color:#484f58;font-style:italic;font-size:0.72rem">${content}</td></tr>`;
      continue;
    }

    rows += `<tr class="${rowCls}" style="border-bottom:1px solid #1c2128">
      <td style="padding:0.3rem 0.6rem;color:#484f58;font-size:0.7rem;text-align:right;font-family:monospace">${refNo}</td>
      <td style="padding:0.3rem 0.6rem;color:#484f58;font-size:0.7rem;text-align:right;font-family:monospace">${curNo}</td>
      <td style="padding:0.3rem 0.5rem;font-family:monospace;font-weight:700;color:${prefixColor}">${prefix}</td>
      <td style="padding:0.3rem 0.6rem"><span class="diff-content">${content}</span></td>
      <td style="padding:0.3rem 0.6rem;white-space:nowrap">${riskBadgeHtml(c.risk_level, c.risk_reason)}</td>
    </tr>`;
  }
  tbody.innerHTML = rows || '<tr><td colspan="5" style="padding:1rem;text-align:center;color:#6e7681">No differences found — configurations are identical.</td></tr>';

  document.getElementById('diffResultWrap').style.display = 'block';
  document.getElementById('diffDownloadBar').style.display = 'block';
}

function downloadDiffReport() {
  if (!_diffResult) return;
  const ref = document.getElementById('refConfig').value;
  const cur = document.getElementById('curConfig').value;
  const s = _diffResult.summary;
  const score = _diffResult.risk_score;

  const riskColor = {critical:'#f85149',high:'#e37300',medium:'#e3b341',low:'#58a6ff',info:'#6e7681'};
  const rowBg = c => {
    if (c.action === 'separator') return '#0d1117';
    if (c.risk_level === 'critical') return 'rgba(248,81,73,0.12)';
    if (c.risk_level === 'high')     return 'rgba(227,130,0,0.10)';
    if (c.risk_level === 'medium')   return 'rgba(227,179,65,0.08)';
    if (c.risk_level === 'low')      return 'rgba(88,166,255,0.06)';
    return c.action === 'add' ? 'rgba(63,185,80,0.04)' : c.action === 'remove' ? 'rgba(248,81,73,0.04)' : 'transparent';
  };

  let tableRows = '';
  for (const c of _diffResult.changes) {
    const bg = rowBg(c);
    const prefix = c.action==='add'?'+':c.action==='remove'?'−':' ';
    const col = c.action==='add'?'#3fb950':c.action==='remove'?'#f85149':'#484f58';
    const content = (c.content||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const rc = riskColor[c.risk_level] || '#6e7681';
    const badge = c.risk_reason ? `<span style="background:${rc}22;color:${rc};padding:0.1rem 0.4rem;border-radius:3px;font-size:0.65rem;font-weight:700;margin-left:0.5rem">${(c.risk_level||'').toUpperCase()}</span><span style="color:#8b949e;font-size:0.7rem;margin-left:0.5rem;font-style:italic">${c.risk_reason}</span>` : '';
    if (c.action === 'separator') {
      tableRows += `<tr><td colspan="5" style="padding:0.25rem;text-align:center;color:#484f58;font-style:italic;font-size:0.72rem">${content}</td></tr>`;
    } else {
      tableRows += `<tr style="background:${bg};border-bottom:1px solid #1c2128">
        <td style="padding:0.25rem 0.5rem;color:#484f58;font-family:monospace;font-size:0.68rem;text-align:right">${c.ref_line_no||''}</td>
        <td style="padding:0.25rem 0.5rem;color:#484f58;font-family:monospace;font-size:0.68rem;text-align:right">${c.cur_line_no||''}</td>
        <td style="padding:0.25rem 0.5rem;font-family:monospace;font-weight:700;color:${col}">${prefix}</td>
        <td style="padding:0.25rem 0.5rem;font-family:monospace;font-size:0.75rem;white-space:pre-wrap;word-break:break-all">${content}</td>
        <td style="padding:0.25rem 0.5rem;white-space:nowrap">${badge}</td>
      </tr>`;
    }
  }

  const now = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';
  const scoreLabel = score >= 20 ? 'CRITICAL' : score >= 10 ? 'HIGH' : score >= 3 ? 'MEDIUM' : 'LOW';
  const scoreCol   = score >= 20 ? '#f85149' : score >= 10 ? '#e37300' : score >= 3 ? '#e3b341' : '#3fb950';

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Config Diff Risk Report</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:1.5rem;font-size:0.82rem}
h1{color:#e6edf3;font-size:1.2rem;margin-bottom:0.25rem}.meta{color:#6e7681;font-size:0.75rem;margin-bottom:1rem}
.pills{display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1.5rem}.pill{padding:0.3rem 0.75rem;border-radius:20px;font-size:0.78rem;font-weight:700}
table{border-collapse:collapse;width:100%;font-size:0.78rem}th{background:#161b22;color:#8b949e;padding:0.4rem 0.6rem;text-align:left;border-bottom:2px solid #30363d}
td{padding:0.3rem 0.5rem;vertical-align:top}</style></head><body>
<h1>Cisco Config Diff — Risk Analysis Report</h1>
<p class="meta">Generated ${now} · +${s.lines_added} added / −${s.lines_removed} removed · ${s.total_changes} total changes</p>
<div class="pills">
  <span class="pill" style="background:${scoreCol}22;color:${scoreCol};border:1px solid ${scoreCol}55">Risk Score: ${score} (${scoreLabel})</span>
  ${s.critical?`<span class="pill" style="background:#f8514922;color:#f85149;border:1px solid #f8514955">${s.critical} Critical</span>`:''}
  ${s.high?`<span class="pill" style="background:#e3730022;color:#e37300;border:1px solid #e3730055">${s.high} High</span>`:''}
  ${s.medium?`<span class="pill" style="background:#e3b34122;color:#e3b341;border:1px solid #e3b34155">${s.medium} Medium</span>`:''}
  ${s.low?`<span class="pill" style="background:#58a6ff22;color:#58a6ff;border:1px solid #58a6ff55">${s.low} Low</span>`:''}
</div>
<table><thead><tr><th>Ref#</th><th>Cur#</th><th></th><th>Config Line</th><th>Risk</th></tr></thead>
<tbody>${tableRows}</tbody></table></body></html>`;

  const blob = new Blob([html], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cisco_config_diff_report.html';
  a.click();
}

// ── AI Config Risk Explanation ────────────────────────────────────────────────
async function explainDiff() {
  if (!_diffResult) return;
  const btn     = document.getElementById('diffExplainBtn');
  const wrap    = document.getElementById('diffExplainWrap');
  const spinner = document.getElementById('diffExplainSpinner');
  const content = document.getElementById('diffExplainContent');
  btn.disabled = true;
  spinner.style.display = 'inline';
  wrap.style.display = 'block';
  content.textContent = '';
  try {
    const resp = await fetch('/config-diff/explain', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({diff_result: _diffResult})
    });
    const data = await resp.json();
    if (data.error) {
      content.textContent = '⚠ ' + data.error;
    } else {
      content.textContent = data.explanation || '(no explanation returned)';
    }
  } catch (e) {
    content.textContent = '⚠ Request failed: ' + e;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

// ── Bulk Config Diff ──────────────────────────────────────────────────────────
let _bulkDiffZipFile = null;
let _bulkDiffFiles   = [];

(function() {
  const inp = document.getElementById('bulkDiffZipInput');
  inp.addEventListener('change', () => {
    if (inp.files[0]) { _bulkDiffZipFile = inp.files[0]; doBulkDiffUpload(''); }
  });
  const dz = document.getElementById('bulkDiffDropZone');
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.style.borderColor = '#58a6ff'; });
  dz.addEventListener('dragleave', () => { dz.style.borderColor = ''; });
  dz.addEventListener('drop', e => {
    e.preventDefault(); dz.style.borderColor = '';
    const f = e.dataTransfer.files[0];
    if (f) { _bulkDiffZipFile = f; doBulkDiffUpload(''); }
  });
})();

function bulkDiffOnDrop(e) { e.preventDefault(); }

async function doBulkDiffUpload(baseline) {
  if (!_bulkDiffZipFile) return;
  const status   = document.getElementById('bulkDiffStatus');
  const progress = document.getElementById('bulkDiffProgressWrap');
  const baseline_wrap = document.getElementById('bulkDiffBaselineWrap');
  status.textContent = '';
  baseline_wrap.style.display = 'none';
  document.getElementById('bulkDiffSummaryBar').style.display    = 'none';
  document.getElementById('bulkDiffDownloadBar').style.display   = 'none';
  document.getElementById('bulkDiffTableWrap').style.display     = 'none';
  progress.style.display = 'block';

  try {
    const fd = new FormData();
    fd.append('zip_file', _bulkDiffZipFile);
    if (baseline) fd.append('baseline', baseline);

    const resp = await fetch('/config-diff/bulk', { method: 'POST', body: fd });
    const data = await resp.json();
    progress.style.display = 'none';

    if (data.error) { status.textContent = 'Error: ' + data.error; return; }

    if (data.needs_baseline) {
      const sel = document.getElementById('bulkDiffBaselineSel');
      sel.innerHTML = data.files.map(f => `<option value="${f}">${f}</option>`).join('');
      baseline_wrap.style.display = 'block';
      status.textContent = `${data.files.length} config files found — select which one is the baseline.`;
      return;
    }

    _bulkDiffFiles = data.files;
    renderBulkDiffSummary(data.stats, data.baseline);
    renderBulkDiffTable(data.files);
    document.getElementById('bulkDiffDownloadLink').href = `/config-diff/bulk-download/${data.job_id}`;
    document.getElementById('bulkDiffDownloadBar').style.display = 'block';
    status.textContent = '';

  } catch(err) {
    progress.style.display = 'none';
    status.textContent = 'Error: ' + err.message;
  }
}

function resubmitBulkDiff() {
  const baseline = document.getElementById('bulkDiffBaselineSel').value;
  if (!baseline) return;
  doBulkDiffUpload(baseline);
}

function renderBulkDiffSummary(s, baseline) {
  const bar = document.getElementById('bulkDiffSummaryBar');
  bar.style.display = 'flex';
  bar.innerHTML = `
    <span class="pill pill-total">${s.total} Files vs <code style="font-size:0.7rem">${baseline}</code></span>
    <span class="pill" style="background:#f8514922;color:#f85149">${s.critical} Critical</span>
    <span class="pill" style="background:#d2992222;color:#d29922">${s.high} High</span>
    <span class="pill" style="background:#388bfd22;color:#388bfd">${s.medium} Medium</span>
    <span class="pill pill-c">${s.low} Low</span>`;
}

function renderBulkDiffTable(files) {
  const tbody = document.getElementById('bulkDiffTbody');
  tbody.innerHTML = files.map((f, i) => {
    const sm = f.summary;
    const lvlBadge = urgencyBadge(f.risk_level);
    return `<tr style="border-bottom:1px solid #21262d">
      <td style="padding:0.4rem 0.75rem;font-weight:600">${f.device}</td>
      <td style="padding:0.4rem 0.75rem;color:#6e7681;font-size:0.75rem;font-family:monospace">${f.name}</td>
      <td style="padding:0.4rem 0.75rem;text-align:right;font-family:monospace;font-weight:700">${f.risk_score}</td>
      <td style="padding:0.4rem 0.75rem">${lvlBadge}</td>
      <td style="padding:0.4rem 0.75rem;text-align:right;color:#f85149">${sm.critical||0}</td>
      <td style="padding:0.4rem 0.75rem;text-align:right;color:#d29922">${sm.high||0}</td>
      <td style="padding:0.4rem 0.75rem;text-align:right;color:#388bfd">${sm.medium||0}</td>
      <td style="padding:0.4rem 0.75rem;text-align:right;color:#3fb950">${sm.low||0}</td>
      <td style="padding:0.4rem 0.75rem;text-align:right;color:#8b949e">${sm.total_changes||0}</td>
      <td style="padding:0.4rem 0.75rem">
        <button class="btn-secondary" style="font-size:0.75rem;padding:0.2rem 0.5rem"
          onclick="downloadBulkDiffReport(${i})">⎙ HTML</button>
      </td>
    </tr>`;
  }).join('');
  document.getElementById('bulkDiffTableWrap').style.display = 'block';
}

function downloadBulkDiffReport(idx) {
  const f = _bulkDiffFiles[idx];
  if (!f) return;
  const s = f.summary;
  const score = f.risk_score;

  const riskColor = {critical:'#f85149',high:'#e37300',medium:'#e3b341',low:'#58a6ff',info:'#6e7681'};
  const rowBg = c => {
    if (c.action === 'separator') return '#0d1117';
    if (c.risk_level === 'critical') return 'rgba(248,81,73,0.12)';
    if (c.risk_level === 'high')     return 'rgba(227,130,0,0.10)';
    if (c.risk_level === 'medium')   return 'rgba(227,179,65,0.08)';
    if (c.risk_level === 'low')      return 'rgba(88,166,255,0.06)';
    return c.action === 'add' ? 'rgba(63,185,80,0.04)' : c.action === 'remove' ? 'rgba(248,81,73,0.04)' : 'transparent';
  };

  let tableRows = '';
  for (const c of f.changes) {
    const bg = rowBg(c);
    const prefix = c.action==='add'?'+':c.action==='remove'?'−':' ';
    const col = c.action==='add'?'#3fb950':c.action==='remove'?'#f85149':'#484f58';
    const content = (c.content||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const rc = riskColor[c.risk_level] || '#6e7681';
    const badge = c.risk_reason ? `<span style="background:${rc}22;color:${rc};padding:0.1rem 0.4rem;border-radius:3px;font-size:0.65rem;font-weight:700;margin-left:0.5rem">${(c.risk_level||'').toUpperCase()}</span><span style="color:#8b949e;font-size:0.7rem;margin-left:0.5rem;font-style:italic">${c.risk_reason}</span>` : '';
    if (c.action === 'separator') {
      tableRows += `<tr><td colspan="5" style="padding:0.25rem;text-align:center;color:#484f58;font-style:italic;font-size:0.72rem">${content}</td></tr>`;
    } else {
      tableRows += `<tr style="background:${bg};border-bottom:1px solid #1c2128">
        <td style="padding:0.25rem 0.5rem;color:#484f58;font-family:monospace;font-size:0.68rem;text-align:right">${c.ref_line_no||''}</td>
        <td style="padding:0.25rem 0.5rem;color:#484f58;font-family:monospace;font-size:0.68rem;text-align:right">${c.cur_line_no||''}</td>
        <td style="padding:0.25rem 0.5rem;font-family:monospace;font-weight:700;color:${col}">${prefix}</td>
        <td style="padding:0.25rem 0.5rem;font-family:monospace;font-size:0.75rem;white-space:pre-wrap;word-break:break-all">${content}</td>
        <td style="padding:0.25rem 0.5rem;white-space:nowrap">${badge}</td>
      </tr>`;
    }
  }

  const now = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';
  const scoreLabel = score >= 20 ? 'CRITICAL' : score >= 10 ? 'HIGH' : score >= 3 ? 'MEDIUM' : 'LOW';
  const scoreCol   = score >= 20 ? '#f85149' : score >= 10 ? '#e37300' : score >= 3 ? '#e3b341' : '#3fb950';

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Config Diff — ${f.device}</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:1.5rem;font-size:0.82rem}
h1{color:#e6edf3;font-size:1.2rem;margin-bottom:0.25rem}.meta{color:#6e7681;font-size:0.75rem;margin-bottom:1rem}
.pills{display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1.5rem}.pill{padding:0.3rem 0.75rem;border-radius:20px;font-size:0.78rem;font-weight:700}
table{border-collapse:collapse;width:100%;font-size:0.78rem}th{background:#161b22;color:#8b949e;padding:0.4rem 0.6rem;text-align:left;border-bottom:2px solid #30363d}
td{padding:0.3rem 0.5rem;vertical-align:top}</style></head><body>
<h1>Cisco Config Diff — ${f.device}</h1>
<p class="meta">Generated ${now} · ${f.name} · +${s.lines_added} added / −${s.lines_removed} removed · ${s.total_changes} total changes</p>
<div class="pills">
  <span class="pill" style="background:${scoreCol}22;color:${scoreCol};border:1px solid ${scoreCol}55">Risk Score: ${score} (${scoreLabel})</span>
  ${s.critical?`<span class="pill" style="background:#f8514922;color:#f85149;border:1px solid #f8514955">${s.critical} Critical</span>`:''}
  ${s.high?`<span class="pill" style="background:#e3730022;color:#e37300;border:1px solid #e3730055">${s.high} High</span>`:''}
  ${s.medium?`<span class="pill" style="background:#e3b34122;color:#e3b341;border:1px solid #e3b34155">${s.medium} Medium</span>`:''}
  ${s.low?`<span class="pill" style="background:#58a6ff22;color:#58a6ff;border:1px solid #58a6ff55">${s.low} Low</span>`:''}
</div>
<table><thead><tr><th>Ref#</th><th>Cur#</th><th></th><th>Config Line</th><th>Risk</th></tr></thead>
<tbody>${tableRows}</tbody></table></body></html>`;

  const blob = new Blob([html], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `cisco_diff_${f.device}.html`;
  a.click();
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
    _send_webhook_alert("eox", stats, job_id)
    _send_email_alert("eox", stats, job_id)
    _record_job_meta(job_id, "eox", stats)

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


@app.route("/html/<job_id>")
def eox_html(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    return _generate_html_report(df, "EOX Compliance Report"), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/swim/html/<job_id>")
def swim_html(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    return _generate_html_report(df, "SWIM Software Report"), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/psirt/html/<job_id>")
def psirt_html(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    return _generate_html_report(df, "PSIRT Security Report"), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/unified/html/<job_id>")
def unified_html(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    return _generate_html_report(df, "Unified Compliance Report"), 200, {"Content-Type": "text/html; charset=utf-8"}


def _generate_html_report(df: pd.DataFrame, title: str) -> str:
    """Generate a self-contained, printable HTML compliance report from a job DataFrame."""
    COMPLIANCE_COLS = {
        "EOX Compliance", "SWIM Compliance", "PSIRT Compliance", "Coverage Status", "Bug Compliance"
    }

    def _cell_style(col: str, val: str) -> str:
        if col not in COMPLIANCE_COLS or not val:
            return ""
        v = val.lower()
        if v in ("compliant", "active"):
            return "background:#0d3320;color:#3fb950"
        if v in ("non-compliant", "inactive"):
            return "background:#3d0c0c;color:#f85149"
        if v in ("warning",):
            return "background:#2d1f00;color:#e3b341"
        if v == "na":
            return "background:#1c1c1c;color:#6e7681"
        return ""

    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    headers = list(df.columns)
    thead = "".join(f"<th>{h}</th>" for h in headers)
    rows_html = ""
    for _, row in df.iterrows():
        cells = ""
        for h in headers:
            v = str(row[h]) if (row[h] is not None and row[h] != "") else ""
            style = _cell_style(h, v)
            style_attr = f' style="{style}"' if style else ""
            cells += f"<td{style_attr}>{v or '—'}</td>"
        rows_html += f"<tr>{cells}</tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background:#0d1117; color:#c9d1d9; margin:0; padding:1.5rem; font-size:0.82rem; }}
  h1   {{ font-size:1.2rem; color:#e6edf3; margin-bottom:0.25rem; }}
  .meta {{ color:#6e7681; margin-bottom:1rem; font-size:0.78rem; }}
  table {{ border-collapse:collapse; width:100%; }}
  th   {{ background:#161b22; color:#8b949e; font-weight:600; text-align:left;
           padding:0.45rem 0.6rem; border-bottom:2px solid #30363d; white-space:nowrap; }}
  td   {{ padding:0.38rem 0.6rem; border-bottom:1px solid #21262d; vertical-align:top; }}
  tr:hover td {{ background:#161b22; }}
  @media print {{
    body {{ background:white; color:black; }}
    tr:hover td {{ background:transparent; }}
  }}
</style>
</head>
<body>
<h1>Cisco EOX Finder — {title}</h1>
<p class="meta">Generated {now} · {len(df)} rows · {len(headers)} columns</p>
<table>
<thead><tr>{thead}</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</body>
</html>"""


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
    _send_webhook_alert("swim", stats, job_id)
    _send_email_alert("swim", stats, job_id)
    _record_job_meta(job_id, "swim", stats)

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
    _send_webhook_alert("psirt", stats, job_id)
    _send_email_alert("psirt", stats, job_id)
    _record_job_meta(job_id, "psirt", stats)

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


@app.route("/bug/search", methods=["POST"])
def bug_search():
    data = request.get_json(force=True)
    pid     = (data.get("pid") or "").strip()
    version = (data.get("version") or "").strip()
    if not pid:
        return jsonify({"error": "Provide a Product ID"}), 400
    if "*" in pid or "," in pid:
        return jsonify({"error": "Bug API requires a single exact PID — no wildcards or commas"}), 400
    try:
        bugs = cisco_bug.get_bugs_by_pid_version(pid, version) if version else cisco_bug.get_bugs_by_pid(pid)
    except Exception as e:
        return jsonify({"error": f"API error: {e}"}), 502
    return jsonify({"result": {
        "pid":        pid,
        "version":    version,
        "bugs":       bugs,
        "compliance": cisco_bug._bug_compliance(bugs),
        "error":      None,
    }})


@app.route("/bug/upload", methods=["POST"])
def bug_upload():
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
        return jsonify({"needs_mapping": True, "available_columns": list(df.columns), "context": "bug"})

    pairs: list[tuple[str, str]] = []
    for _, row in df.iterrows():
        pid_val = str(row[pid_col]).strip()
        if not pid_val:
            continue
        ver = str(row[version_col]).strip() if version_col else ""
        pairs.append((pid_val.upper(), ver))

    unique_pairs = list(dict.fromkeys(pairs))
    try:
        bug_lookup = _build_bug_lookup(unique_pairs)
    except Exception as e:
        return jsonify({"error": f"Bug API error: {e}"}), 502

    bug_col_names = [c[0] for c in BUG_COLS]
    for col_name in bug_col_names:
        df[col_name] = ""

    for idx, row in df.iterrows():
        pid_val = str(row[pid_col]).strip()
        if not pid_val:
            df.at[idx, "Bug Compliance"] = "NA"
            continue
        ver = str(row[version_col]).strip() if version_col else ""
        rec = bug_lookup.get((pid_val.upper(), ver.lower())) or {}
        df.at[idx, "Bug Compliance"]  = rec.get("bug_compliance", "")
        df.at[idx, "Bug Open Count"]  = str(rec.get("open_count", "")) if rec else ""
        df.at[idx, "Bug IDs"]         = rec.get("bug_ids", "")
        df.at[idx, "Bug Fixed Count"] = str(rec.get("critical_count", "")) if rec else ""

    comp_col = df["Bug Compliance"]
    stats = {
        "total":        len(df),
        "unique_pids":  len(unique_pairs),
        "compliant":    int((comp_col == "Compliant").sum()),
        "non_compliant": int((comp_col == "Non-Compliant").sum()),
        "na":           int(((comp_col == "NA") | (comp_col == "")).sum()),
    }

    job_id = str(uuid.uuid4())[:8]
    _store_job(job_id, df)
    _record_job_meta(job_id, "bug", stats)
    _send_webhook_alert("bug", stats, job_id)
    _send_email_alert("bug", stats, job_id)

    return jsonify({
        "job_id":        job_id,
        "pid_col":       pid_col,
        "version_col":   version_col,
        "headers":       list(df.columns),
        "bug_col_names": bug_col_names,
        "rows":          df.to_dict(orient="records"),
        "stats":         stats,
    })


@app.route("/bug/download/<job_id>")
def bug_download(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    buf = io.BytesIO()
    df.to_excel(buf, index=False, engine="openpyxl")
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        download_name="cisco_bug_enriched.xlsx",
        as_attachment=True,
    )


@app.route("/bug/html/<job_id>")
def bug_html(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    return _generate_html_report(df, "Bug Compliance Report"), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/config-diff/analyze", methods=["POST"])
def config_diff_analyze():
    data = request.get_json(force=True)
    reference = (data.get("reference") or "").strip()
    current   = (data.get("current")   or "").strip()
    min_risk  = (data.get("min_risk")  or "info").strip().lower()
    if not reference or not current:
        return jsonify({"error": "Both 'reference' and 'current' config text are required"}), 400

    ref_lines = reference.splitlines(keepends=True)
    cur_lines = current.splitlines(keepends=True)
    result    = cisco_config_diff.analyze_diff(ref_lines, cur_lines)

    # Apply min_risk filter on the changes list (keep context/separator for display)
    min_rank = cisco_config_diff.RISK_ORDER.get(min_risk, 0)
    result["changes"] = [
        c for c in result["changes"]
        if c["action"] in ("context", "separator")
        or cisco_config_diff.RISK_ORDER.get(c["risk_level"], 0) >= min_rank
    ]
    return jsonify(result)


_BULK_DIFF_EXTS     = {'.cfg', '.txt', '.conf', '.log'}
_BULK_DIFF_BASELINE = {'baseline.cfg', 'baseline.txt', 'baseline.conf',
                       'reference.cfg', 'reference.txt', 'reference.conf'}
_BULK_DIFF_MAX      = 50


@app.route("/config-diff/bulk", methods=["POST"])
def config_diff_bulk():
    if "zip_file" not in request.files:
        return jsonify({"error": "No ZIP file provided"}), 400
    zf = request.files["zip_file"]
    baseline_name = request.form.get("baseline", "").strip()

    try:
        zip_bytes = zf.read()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            config_names = [
                n for n in z.namelist()
                if not n.endswith('/')
                and os.path.splitext(n.lower())[1] in _BULK_DIFF_EXTS
            ]
    except zipfile.BadZipFile:
        return jsonify({"error": "Invalid or corrupt ZIP file"}), 400

    if not config_names:
        return jsonify({"error": "No config files (.cfg, .txt, .conf, .log) found in ZIP"}), 400
    if len(config_names) > _BULK_DIFF_MAX:
        return jsonify({"error": f"ZIP contains more than {_BULK_DIFF_MAX} config files"}), 400

    if not baseline_name:
        for name in config_names:
            if os.path.basename(name).lower() in _BULK_DIFF_BASELINE:
                baseline_name = name
                break

    if not baseline_name or baseline_name not in config_names:
        return jsonify({"needs_baseline": True, "files": config_names})

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        ref_text  = z.read(baseline_name).decode('utf-8', errors='replace')
        ref_lines = ref_text.splitlines(keepends=True)
        per_file  = []
        for name in config_names:
            if name == baseline_name:
                continue
            cur_text  = z.read(name).decode('utf-8', errors='replace')
            cur_lines = cur_text.splitlines(keepends=True)
            result    = cisco_config_diff.analyze_diff(ref_lines, cur_lines)
            score     = result["risk_score"]
            level     = ("Critical" if score >= 20 else "High" if score >= 10
                         else "Medium" if score >= 3 else "Low")
            per_file.append({
                "name":       name,
                "device":     os.path.splitext(os.path.basename(name))[0],
                "risk_score": score,
                "risk_level": level,
                "summary":    result["summary"],
                "changes":    result["changes"],
            })

    per_file.sort(key=lambda x: x["risk_score"], reverse=True)

    rows = [{
        "Device":        f["device"],
        "Filename":      f["name"],
        "Risk Score":    f["risk_score"],
        "Risk Level":    f["risk_level"],
        "Critical":      f["summary"].get("critical", 0),
        "High":          f["summary"].get("high", 0),
        "Medium":        f["summary"].get("medium", 0),
        "Low":           f["summary"].get("low", 0),
        "Total Changes": f["summary"].get("total_changes", 0),
        "Lines Added":   f["summary"].get("lines_added", 0),
        "Lines Removed": f["summary"].get("lines_removed", 0),
    } for f in per_file]
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Device", "Filename", "Risk Score", "Risk Level",
                 "Critical", "High", "Medium", "Low",
                 "Total Changes", "Lines Added", "Lines Removed"])

    stats = {
        "total":    len(per_file),
        "critical": sum(1 for f in per_file if f["risk_level"] == "Critical"),
        "high":     sum(1 for f in per_file if f["risk_level"] == "High"),
        "medium":   sum(1 for f in per_file if f["risk_level"] == "Medium"),
        "low":      sum(1 for f in per_file if f["risk_level"] == "Low"),
        "baseline": baseline_name,
    }
    job_id = str(uuid.uuid4())[:8]
    _store_job(job_id, df)
    _record_job_meta(job_id, "configdiff", stats)

    return jsonify({"job_id": job_id, "baseline": baseline_name,
                    "files": per_file, "stats": stats})


@app.route("/config-diff/bulk-download/<job_id>")
def config_diff_bulk_download(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    buf = io.BytesIO()
    df.to_excel(buf, index=False, engine="openpyxl")
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        download_name="cisco_bulk_config_diff.xlsx",
        as_attachment=True,
    )


@app.route("/config-diff/baselines", methods=["GET"])
def baselines_list():
    return jsonify(_list_baselines())


@app.route("/config-diff/baselines", methods=["POST"])
def baselines_save():
    data    = request.get_json(force=True) or {}
    name    = (data.get("name") or "").strip()
    content = (data.get("content") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    if not content:
        return jsonify({"error": "content is required"}), 400
    bid = _save_baseline(name, content)
    return jsonify({"baseline_id": bid, "name": name})


@app.route("/config-diff/baselines/<bid>", methods=["GET"])
def baselines_get(bid: str):
    b = _load_baseline(bid)
    if b is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(b)


@app.route("/config-diff/baselines/<bid>", methods=["DELETE"])
def baselines_delete(bid: str):
    if not _delete_baseline(bid):
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@app.route("/config-diff/explain", methods=["POST"])
def config_diff_explain():
    try:
        client = _get_anthropic_client()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503

    data = request.get_json(force=True) or {}
    diff_result = data.get("diff_result")
    if not diff_result:
        return jsonify({"error": "diff_result is required"}), 400

    # Build a compact summary for the user message — omit context/separator lines
    # to keep the prompt tight.
    summary  = diff_result.get("summary", {})
    score    = diff_result.get("risk_score", 0)
    changes  = [
        c for c in (diff_result.get("changes") or [])
        if c.get("action") not in ("context", "separator") and c.get("risk_reason")
    ]
    # Truncate to 80 most-risky entries so we don't blow the context window
    risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    changes.sort(key=lambda c: risk_order.get(c.get("risk_level", "info"), 0), reverse=True)
    changes = changes[:80]

    change_lines = "\n".join(
        f"[{c.get('risk_level','info').upper()}] {c.get('action','?').upper()} "
        f"line {c.get('ref_line_no') or c.get('cur_line_no','?')}: "
        f"{(c.get('content') or '').strip()!r} — {c.get('risk_reason','')}"
        for c in changes
    )
    user_msg = (
        f"Risk Score: {score}\n"
        f"Critical: {summary.get('critical',0)}, High: {summary.get('high',0)}, "
        f"Medium: {summary.get('medium',0)}, Low: {summary.get('low',0)}\n"
        f"Lines added: {summary.get('lines_added',0)}, removed: {summary.get('lines_removed',0)}\n\n"
        f"Annotated diff entries:\n{change_lines or '(none — configurations may be identical)'}"
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": _EXPLAIN_SYSTEM,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_msg}],
        )
        explanation = response.content[0].text
    except Exception as exc:
        return jsonify({"error": f"Claude API error: {exc}"}), 502

    return jsonify({"explanation": explanation})


@app.route("/import/netbox", methods=["POST"])
def import_netbox():
    data   = request.get_json(force=True) or {}
    url    = (data.get("url") or "").rstrip("/")
    token  = (data.get("token") or "").strip()
    limit  = min(int(data.get("limit") or 200), 1000)
    if not url or not token:
        return jsonify({"error": "url and token are required"}), 400
    try:
        import requests as _req
        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
        resp    = _req.get(f"{url}/api/dcim/devices/",
                           params={"limit": limit}, headers=headers, timeout=15)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception as exc:
        return jsonify({"error": f"NetBox request failed: {exc}"}), 502

    devices = []
    for d in results:
        pid    = (d.get("device_type") or {}).get("model", "")
        serial = d.get("serial", "")
        name   = d.get("name", "")
        site   = (d.get("site") or {}).get("name", "")
        devices.append({"Device Name": name, "Product ID": pid,
                        "Serial Number": serial, "Site": site})
    return jsonify({"source": "netbox", "count": len(devices), "devices": devices})


@app.route("/import/servicenow", methods=["POST"])
def import_servicenow():
    data     = request.get_json(force=True) or {}
    url      = (data.get("url") or "").rstrip("/")
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    table    = (data.get("table") or "cmdb_ci_ip_switch").strip()
    limit    = min(int(data.get("limit") or 200), 1000)
    if not url or not username or not password:
        return jsonify({"error": "url, username, and password are required"}), 400
    try:
        import requests as _req
        fields = "name,model_id,serial_number,location"
        resp   = _req.get(
            f"{url}/api/now/table/{table}",
            params={"sysparm_limit": limit, "sysparm_fields": fields},
            auth=(username, password),
            headers={"Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        results = resp.json().get("result", [])
    except Exception as exc:
        return jsonify({"error": f"ServiceNow request failed: {exc}"}), 502

    devices = []
    for d in results:
        pid      = (d.get("model_id") or {}).get("display_value", "") or d.get("model_id", "")
        serial   = d.get("serial_number", "")
        name     = d.get("name", "")
        location = (d.get("location") or {}).get("display_value", "") or d.get("location", "")
        devices.append({"Device Name": name, "Product ID": pid,
                        "Serial Number": serial, "Location": location})
    return jsonify({"source": "servicenow", "count": len(devices), "devices": devices})


@app.route("/unified/upload", methods=["POST"])
def unified_upload():
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

    PID_KEYWORDS = ["product part", "pid", "part number", "part_no", "model", "pn"]
    SN_KEYWORDS  = ["serial number", "s/n", "serial_no", "serial"]

    pid_col      = request.form.get("pid_col", "").strip()      or _find_col(df, PID_KEYWORDS)
    sn_col       = request.form.get("sn_col", "").strip()       or _find_col(df, SN_KEYWORDS)
    version_col  = request.form.get("version_col", "").strip()  or _find_col(df, SWIM_VERSION_KEYWORDS)
    os_type_col  = request.form.get("os_type_col", "").strip()  or _find_col(df, OS_TYPE_KEYWORDS)
    default_os_type = request.form.get("default_os_type", "iosxe").strip().lower()

    if not pid_col and not sn_col:
        return jsonify({"needs_mapping": True, "available_columns": list(df.columns), "context": "unified"})

    # ── EOX lookup ────────────────────────────────────────────────────────────
    unique_pids = list(dict.fromkeys(
        str(row[pid_col]).strip().upper() for _, row in df.iterrows()
        if pid_col and str(row[pid_col]).strip()
    ))
    unique_sns = list(dict.fromkeys(
        str(row[sn_col]).strip().upper() for _, row in df.iterrows()
        if sn_col and str(row[sn_col]).strip()
    ))

    try:
        pid_lookup = _build_pid_lookup(unique_pids) if unique_pids else {}
        sn_lookup  = _build_sn_lookup(unique_sns)   if unique_sns  else {}
    except Exception as e:
        return jsonify({"error": f"EOX API error: {e}"}), 502

    # ── Coverage lookup (SN2INFO) ─────────────────────────────────────────────
    try:
        coverage_lookup = _build_coverage_lookup(unique_sns) if unique_sns else {}
    except Exception as e:
        return jsonify({"error": f"Coverage API error: {e}"}), 502

    # ── SWIM lookup — use resolved orderable_pid when no pid_col ──────────────
    swim_pids: list[str] = []
    for _, row in df.iterrows():
        if pid_col:
            p = str(row[pid_col]).strip().upper()
            if p:
                swim_pids.append(p)
        elif sn_col:
            sn = str(row[sn_col]).strip().upper()
            cov = coverage_lookup.get(sn) or {}
            p = (cov.get("orderable_pid") or cov.get("base_pid") or "").upper()
            if p:
                swim_pids.append(p)

    unique_swim_pids = list(dict.fromkeys(swim_pids))
    try:
        swim_lookup = _build_swim_lookup(unique_swim_pids) if unique_swim_pids else {}
    except Exception as e:
        return jsonify({"error": f"SWIM API error: {e}"}), 502

    # ── PSIRT lookup ──────────────────────────────────────────────────────────
    psirt_pairs: list[tuple[str, str]] = []
    if version_col:
        for _, row in df.iterrows():
            ver = str(row[version_col]).strip()
            if not ver:
                continue
            ost = str(row[os_type_col]).strip().lower() if os_type_col else default_os_type
            if not ost or ost not in cisco_psirt.OS_TYPES:
                ost = default_os_type
            psirt_pairs.append((ost, ver))

    unique_psirt_pairs = list(dict.fromkeys(psirt_pairs))
    try:
        psirt_lookup = _build_psirt_lookup(unique_psirt_pairs) if unique_psirt_pairs else {}
    except Exception as e:
        return jsonify({"error": f"PSIRT API error: {e}"}), 502

    # ── Bug lookup ────────────────────────────────────────────────────────────
    bug_pairs: list[tuple[str, str]] = []
    for _, row in df.iterrows():
        eff_pid = ""
        if pid_col:
            eff_pid = str(row[pid_col]).strip().upper()
        elif sn_col:
            sn = str(row[sn_col]).strip().upper()
            cov = coverage_lookup.get(sn) or {}
            eff_pid = (cov.get("orderable_pid") or cov.get("base_pid") or "").upper()
        if eff_pid:
            ver = str(row[version_col]).strip() if version_col else ""
            bug_pairs.append((eff_pid, ver))

    unique_bug_pairs = list(dict.fromkeys(bug_pairs))
    try:
        bug_lookup = _build_bug_lookup(unique_bug_pairs) if unique_bug_pairs else {}
    except Exception as e:
        return jsonify({"error": f"Bug API error: {e}"}), 502

    # ── Add enriched columns ─────────────────────────────────────────────────
    eox_col_names     = [c[0] for c in EOX_COLS]
    cov_col_names     = [c[0] for c in COVERAGE_COLS]
    swim_col_names    = [c[0] for c in SWIM_COLS]
    psirt_col_names   = [c[0] for c in PSIRT_COLS]
    bug_col_names     = [c[0] for c in BUG_COLS]
    urgency_col_names = [c[0] for c in URGENCY_COLS]

    for name in eox_col_names + cov_col_names + swim_col_names + psirt_col_names + bug_col_names + urgency_col_names:
        df[name] = ""

    for idx, row in df.iterrows():
        # Resolve EOX record (pid_col first, else sn_col)
        eox_rec = {}
        if pid_col:
            p = str(row[pid_col]).strip().upper()
            eox_rec = pid_lookup.get(p) or {}
        elif sn_col:
            sn = str(row[sn_col]).strip().upper()
            eox_rec = sn_lookup.get(sn) or {}

        comp = eox_rec.get("compliance") or {}
        df.at[idx, "EOX End of Sale"]             = eox_rec.get("end_of_sale", "")
        df.at[idx, "EOX End of SW Maintenance"]   = eox_rec.get("end_of_sw_maintenance", "")
        df.at[idx, "EOX End of Security Support"] = eox_rec.get("end_of_security_support", "")
        df.at[idx, "EOX End of Service Contract"] = eox_rec.get("end_of_service_contract", "")
        df.at[idx, "EOX Last Date of Support"]    = eox_rec.get("last_date_of_support", "")
        df.at[idx, "EOX Compliance"]              = comp.get("label", "")
        df.at[idx, "EOX Migration PID"]           = eox_rec.get("migration_product_id", "")

        # Coverage
        cov_rec = {}
        if sn_col:
            sn = str(row[sn_col]).strip().upper()
            cov_rec = coverage_lookup.get(sn) or {}
        df.at[idx, "Coverage Status"]   = cov_rec.get("coverage_status", "")
        df.at[idx, "Coverage End Date"] = cov_rec.get("coverage_end_date", "")
        df.at[idx, "Contract Number"]   = cov_rec.get("contract_number", "")
        df.at[idx, "Service Level"]     = cov_rec.get("service_level", "")

        # SWIM — resolve effective PID
        swim_pid = ""
        if pid_col:
            swim_pid = str(row[pid_col]).strip().upper()
        elif sn_col:
            sn = str(row[sn_col]).strip().upper()
            swim_pid = (cov_rec.get("orderable_pid") or cov_rec.get("base_pid") or "").upper()

        swim_rec = swim_lookup.get(swim_pid) or {} if swim_pid else {}
        df.at[idx, "SWIM Suggested Release"] = swim_rec.get("suggested_release", "")
        df.at[idx, "SWIM Lifecycle"]         = swim_rec.get("lifecycle", "")
        df.at[idx, "SWIM Compliance"]        = swim_rec.get("swim_compliance", "")

        # PSIRT
        if version_col:
            ver = str(row[version_col]).strip()
            if not ver:
                df.at[idx, "PSIRT Compliance"] = "NA"
            else:
                ost = str(row[os_type_col]).strip().lower() if os_type_col else default_os_type
                if not ost or ost not in cisco_psirt.OS_TYPES:
                    ost = default_os_type
                prec = psirt_lookup.get((ost, ver.lower())) or {}
                df.at[idx, "PSIRT Compliance"]          = prec.get("compliance", "")
                df.at[idx, "PSIRT Critical Advisories"] = str(prec.get("critical_count", "")) if prec else ""
                df.at[idx, "PSIRT Advisory IDs"]        = prec.get("advisory_ids", "")
                df.at[idx, "PSIRT CVEs"]                = prec.get("cves", "")
        else:
            df.at[idx, "PSIRT Compliance"] = "NA"

        # Bug
        bug_pid = swim_pid  # reuse already-resolved effective PID
        if not bug_pid:
            df.at[idx, "Bug Compliance"] = "NA"
        else:
            ver = str(row[version_col]).strip() if version_col else ""
            brec = bug_lookup.get((bug_pid.upper(), ver.lower())) or {}
            df.at[idx, "Bug Compliance"]  = brec.get("bug_compliance", "")
            df.at[idx, "Bug Open Count"]  = str(brec.get("open_count", "")) if brec else ""
            df.at[idx, "Bug IDs"]         = brec.get("bug_ids", "")
            df.at[idx, "Bug Fixed Count"] = str(brec.get("critical_count", "")) if brec else ""

        # Urgency Score
        score, level = _compute_urgency(row.to_dict())
        df.at[idx, "Urgency Score"] = score
        df.at[idx, "Urgency Level"] = level

    # ── Stats ─────────────────────────────────────────────────────────────────
    cov_col     = df["Coverage Status"]
    psirt_col   = df["PSIRT Compliance"]
    bug_col     = df["Bug Compliance"]
    urgency_col = df["Urgency Level"]
    stats = {
        "total":               len(df),
        "coverage_active":    int((cov_col == "Active").sum()),
        "coverage_inactive":  int((cov_col == "Inactive").sum()),
        "coverage_unknown":   int(((cov_col == "") | (cov_col.isna())).sum()),
        "psirt_compliant":     int((psirt_col == "Compliant").sum()),
        "psirt_non_compliant": int((psirt_col == "Non-Compliant").sum()),
        "psirt_na":            int(((psirt_col == "NA") | (psirt_col == "")).sum()),
        "bug_compliant":       int((bug_col == "Compliant").sum()),
        "bug_non_compliant":   int((bug_col == "Non-Compliant").sum()),
        "bug_na":              int(((bug_col == "NA") | (bug_col == "")).sum()),
        "urgency_critical":    int((urgency_col == "Critical").sum()),
        "urgency_high":        int((urgency_col == "High").sum()),
        "urgency_medium":      int((urgency_col == "Medium").sum()),
        "urgency_low":         int((urgency_col == "Low").sum()),
    }

    job_id = str(uuid.uuid4())[:8]
    _store_job(job_id, df)
    _send_webhook_alert("unified", stats, job_id)
    _send_email_alert("unified", stats, job_id)
    _record_job_meta(job_id, "unified", stats)

    return jsonify({
        "job_id":          job_id,
        "pid_col":         pid_col,
        "sn_col":          sn_col,
        "version_col":     version_col,
        "os_type_col":     os_type_col,
        "default_os_type": default_os_type,
        "headers":         list(df.columns),
        "col_meta": {
            "eox":     eox_col_names,
            "cov":     cov_col_names,
            "swim":    swim_col_names,
            "psirt":   psirt_col_names,
            "bug":     bug_col_names,
            "urgency": urgency_col_names,
        },
        "rows":  df.to_dict(orient="records"),
        "stats": stats,
    })


@app.route("/unified/download/<job_id>")
def unified_download(job_id: str):
    df = _load_job(job_id)
    if df is None:
        return "Job not found or expired", 404
    buf = io.BytesIO()
    df.to_excel(buf, index=False, engine="openpyxl")
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        download_name="cisco_unified_report.xlsx",
        as_attachment=True,
    )


@app.route("/dashboard/data")
def dashboard_data():
    import json as _json
    with _db() as conn:
        rows = conn.execute(
            "SELECT job_id, job_type, stats_json, created_at FROM job_meta "
            "ORDER BY created_at DESC LIMIT 90"
        ).fetchall()
    jobs = [
        {"job_id": r[0], "job_type": r[1],
         "stats": _json.loads(r[2]), "created_at": r[3]}
        for r in rows
    ]
    return jsonify(jobs)


@app.route("/lists", methods=["GET"])
def get_lists():
    return jsonify(_list_saved_lists())


@app.route("/lists/save", methods=["POST"])
def save_list():
    data = request.get_json(force=True)
    name    = (data.get("name") or "").strip()
    columns = data.get("columns") or []
    rows    = data.get("rows") or []
    if not name:
        return jsonify({"error": "List name is required"}), 400
    if not columns:
        return jsonify({"error": "No columns provided"}), 400
    list_id = _save_list(name, columns, rows)
    return jsonify({"list_id": list_id, "name": name})


@app.route("/lists/<list_id>", methods=["DELETE"])
def delete_list(list_id: str):
    if not _delete_saved_list(list_id):
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@app.route("/nvd/cve", methods=["POST"])
def nvd_cve():
    """Fetch CVE details from NIST NVD API v2 (no key required for basic queries)."""
    data    = request.get_json(force=True) or {}
    cve_ids = [c.strip().upper() for c in (data.get("cves") or []) if c.strip()]
    if not cve_ids:
        return jsonify({"error": "cves list is required"}), 400
    cve_ids = cve_ids[:10]  # cap per request

    import requests as _req
    results = []
    for cve_id in cve_ids:
        try:
            resp = _req.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id}, timeout=10,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            if not items:
                results.append({"cve_id": cve_id, "error": "Not found in NVD"})
                continue
            cve  = items[0]["cve"]
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
            cvss_v2 = (metrics.get("cvssMetricV2") or [{}])[0]
            score_v3  = (cvss_v3.get("cvssData") or {}).get("baseScore")
            vector_v3 = (cvss_v3.get("cvssData") or {}).get("vectorString")
            score_v2  = (cvss_v2.get("cvssData") or {}).get("baseScore")
            severity  = (cvss_v3.get("cvssData") or {}).get("baseSeverity") or cvss_v2.get("baseSeverity", "")
            results.append({
                "cve_id":      cve_id,
                "description": desc,
                "cvss_v3":     score_v3,
                "cvss_v2":     score_v2,
                "severity":    severity,
                "vector":      vector_v3,
                "published":   cve.get("published", "")[:10],
                "modified":    cve.get("lastModified", "")[:10],
                "references":  [r["url"] for r in cve.get("references", [])[:3]],
                "nvd_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        except Exception as exc:
            results.append({"cve_id": cve_id, "error": str(exc)})
    return jsonify({"results": results})


@app.route("/settings/email-config")
def settings_email_config():
    return jsonify({
        "smtp_host":    _SMTP_HOST or None,
        "smtp_port":    _SMTP_PORT,
        "smtp_user":    _SMTP_USER or None,
        "alert_to":     _ALERT_TO  or None,
        "alert_from":   _ALERT_FROM or None,
        "min_noncompliant": _ALERT_MIN_NC,
        "configured":   _smtp_configured(),
    })


@app.route("/settings/test-email", methods=["POST"])
def settings_test_email():
    if not _smtp_configured():
        return jsonify({"ok": False, "error": "SMTP_HOST and ALERT_EMAIL_TO env vars are required"}), 400
    err = _send_email_alert(
        "test",
        {"total": 1, "non_compliant": 1, "note": "This is a test alert from Cisco EOX Finder"},
        "TEST",
        subject_override="[Cisco EOX Finder] Test Email — Configuration Verified",
    )
    if err:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True, "sent_to": _ALERT_TO})


# ── REST API v1 ───────────────────────────────────────────────────────────────
_API_KEY = os.getenv("API_KEY", "")


def _api_auth() -> bool:
    """Return True if the request is authorized (or no key configured)."""
    if not _API_KEY:
        return True
    provided = (request.headers.get("X-API-Key") or
                request.args.get("api_key") or "")
    return provided == _API_KEY


def _api_err(msg: str, code: int = 400):
    return jsonify({"ok": False, "data": None, "error": msg}), code


def _api_ok(data):
    return jsonify({"ok": True, "data": data, "error": None})


@app.route("/api/v1/")
def api_index():
    return _api_ok({
        "version": "1",
        "endpoints": [
            {"method": "GET",  "path": "/api/v1/eox",         "params": ["pid", "sn"]},
            {"method": "GET",  "path": "/api/v1/swim",        "params": ["pid"]},
            {"method": "GET",  "path": "/api/v1/psirt",       "params": ["os_type", "version"]},
            {"method": "GET",  "path": "/api/v1/bug",         "params": ["pid", "version (opt)"]},
            {"method": "POST", "path": "/api/v1/config-diff", "body":  {"reference": "str", "current": "str", "min_risk": "info|low|medium|high|critical"}},
            {"method": "GET",  "path": "/api/v1/jobs",        "params": ["limit (opt, default 20)"]},
        ],
        "auth": "X-API-Key header or ?api_key= query param (required when API_KEY env var is set)",
    })


@app.route("/api/v1/eox")
def api_eox():
    if not _api_auth():
        return _api_err("Unauthorized", 401)
    pid = request.args.get("pid", "").strip()
    sn  = request.args.get("sn",  "").strip()
    if not pid and not sn:
        return _api_err("Provide 'pid' or 'sn' query parameter")
    try:
        if pid:
            result = cisco_eox.query_by_product_id(pid)
        else:
            result = cisco_eox.query_by_serial_number(sn)
    except Exception as exc:
        return _api_err(str(exc), 502)
    return _api_ok(result)


@app.route("/api/v1/swim")
def api_swim():
    if not _api_auth():
        return _api_err("Unauthorized", 401)
    pid = request.args.get("pid", "").strip()
    if not pid:
        return _api_err("Provide 'pid' query parameter")
    try:
        result = cisco_swim.get_suggested_release(pid)
    except Exception as exc:
        return _api_err(str(exc), 502)
    return _api_ok(result)


@app.route("/api/v1/psirt")
def api_psirt():
    if not _api_auth():
        return _api_err("Unauthorized", 401)
    os_type = request.args.get("os_type", "iosxe").strip().lower()
    version = request.args.get("version", "").strip()
    if not version:
        return _api_err("Provide 'version' query parameter")
    if os_type not in cisco_psirt.OS_TYPES:
        return _api_err(f"Invalid os_type. Valid values: {', '.join(cisco_psirt.OS_TYPES)}")
    try:
        result = cisco_psirt.query_psirt_by_version(os_type, version)
    except Exception as exc:
        return _api_err(str(exc), 502)
    return _api_ok(result)


@app.route("/api/v1/bug")
def api_bug():
    if not _api_auth():
        return _api_err("Unauthorized", 401)
    pid     = request.args.get("pid",     "").strip()
    version = request.args.get("version", "").strip()
    if not pid:
        return _api_err("Provide 'pid' query parameter")
    try:
        bugs = (cisco_bug.get_bugs_by_pid_version(pid, version)
                if version else cisco_bug.get_bugs_by_pid(pid))
    except Exception as exc:
        return _api_err(str(exc), 502)
    return _api_ok({"pid": pid, "version": version, "bugs": bugs,
                    "compliance": cisco_bug._bug_compliance(bugs)})


@app.route("/api/v1/config-diff", methods=["POST"])
def api_config_diff():
    if not _api_auth():
        return _api_err("Unauthorized", 401)
    body      = request.get_json(force=True) or {}
    reference = (body.get("reference") or "").strip()
    current   = (body.get("current")   or "").strip()
    min_risk  = (body.get("min_risk")  or "info").strip().lower()
    if not reference or not current:
        return _api_err("Both 'reference' and 'current' fields are required")
    result   = cisco_config_diff.analyze_diff(
        reference.splitlines(keepends=True),
        current.splitlines(keepends=True),
    )
    min_rank = cisco_config_diff.RISK_ORDER.get(min_risk, 0)
    result["changes"] = [
        c for c in result["changes"]
        if c["action"] in ("context", "separator")
        or cisco_config_diff.RISK_ORDER.get(c["risk_level"], 0) >= min_rank
    ]
    return _api_ok(result)


@app.route("/api/v1/jobs")
def api_jobs():
    if not _api_auth():
        return _api_err("Unauthorized", 401)
    import json as _json
    limit = min(int(request.args.get("limit", 20)), 90)
    with _db() as conn:
        rows = conn.execute(
            "SELECT job_id, job_type, stats_json, created_at FROM job_meta "
            "ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return _api_ok([
        {"job_id": r[0], "job_type": r[1],
         "stats": _json.loads(r[2]), "created_at": r[3]}
        for r in rows
    ])


if __name__ == "__main__":
    print("Cisco EOX Finder running at http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
