"""
Cisco Bug API v2.0 Client
Queries known defects (CSCxxx IDs) by Product ID and optional software version.
Reuses OAuth2 credentials and token cache from cisco_eox.

CLI Usage:
  python cisco_bug.py --pid WS-C3560-48PS-S
  python cisco_bug.py --pid WS-C3560-48PS-S --version "12.2(25)SEE2"
  python cisco_bug.py --pid WS-C3560-48PS-S --json
  python cisco_bug.py --batch-file devices.txt
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from cisco_eox import get_access_token

BUG_BASE_URL = "https://apix.cisco.com/bug/v2.0/bugs"

SEVERITY_MAP = {1: "Critical", 2: "High", 3: "Moderate", 4: "Minor"}
STATUS_MAP   = {"O": "Open", "F": "Fixed", "T": "Terminated", "E": "Unreproducible", "D": "Duplicate"}

# Lower number = more severe: 1=Critical, 2=High, 3=Moderate, 4=Minor.
# Default 2 means Critical + High bugs trigger Non-Compliant.
BUG_SEVERITY_THRESHOLD = int(os.getenv("BUG_SEVERITY_THRESHOLD", "2"))


def _bug_request(path: str, params: dict | None = None, _retries: int = 3) -> list[dict]:
    """Authenticated GET with exponential backoff on 429. Returns flat bugs list (all pages)."""
    url = f"{BUG_BASE_URL}/{path}"
    all_bugs: list[dict] = []
    page = 1
    while True:
        p = dict(params or {})
        if page > 1:
            p["pageIndex"] = page
        for attempt in range(_retries + 1):
            resp = requests.get(
                url,
                params=p or None,
                headers={
                    "Authorization": f"Bearer {get_access_token()}",
                    "Accept": "application/json",
                },
                timeout=15,
            )
            if resp.status_code == 429 and attempt < _retries:
                time.sleep(2 ** attempt)
                continue
            if resp.status_code in (400, 404):
                try:
                    body = resp.json()
                    print(
                        f"Bug API {resp.status_code} for {path}: "
                        f"{body.get('errorDescription', resp.text)}",
                        file=sys.stderr,
                    )
                except Exception:
                    print(f"Bug API {resp.status_code} for {path}: {resp.text}", file=sys.stderr)
                return all_bugs
            resp.raise_for_status()
            break
        else:
            resp.raise_for_status()

        data = resp.json()
        page_bugs = data.get("bugs") or []
        all_bugs.extend(page_bugs)
        if len(page_bugs) < 10:
            break
        page += 1

    return all_bugs


def _parse_bug(bug: dict) -> dict:
    """Flatten one bug entry from the Bug API response."""
    try:
        sev = int(bug.get("severity", 0))
    except (ValueError, TypeError):
        sev = 0
    return {
        "bug_id":                  bug.get("bug_id", ""),
        "headline":                bug.get("headline", ""),
        "severity":                sev,
        "severity_label":          SEVERITY_MAP.get(sev, ""),
        "status":                  bug.get("status", ""),
        "status_label":            STATUS_MAP.get(bug.get("status", ""), ""),
        "product":                 bug.get("product", ""),
        "base_pid":                bug.get("base_pid", ""),
        "known_affected_releases": bug.get("known_affected_releases", ""),
        "known_fixed_releases":    bug.get("known_fixed_releases", ""),
        "created_date":            bug.get("created_date", ""),
        "last_modified_date":      bug.get("last_modified_date", ""),
        "support_case_count":      bug.get("support_case_count", ""),
    }


def _bug_compliance(bugs: list[dict]) -> str:
    """Returns 'Non-Compliant' if any open bug meets the severity threshold, else 'Compliant'."""
    for bug in bugs:
        if bug.get("status") == "O" and 0 < bug.get("severity", 0) <= BUG_SEVERITY_THRESHOLD:
            return "Non-Compliant"
    return "Compliant"


def get_bugs_by_pid(pid: str) -> list[dict]:
    """Return all normalized bugs for a PID (all pages)."""
    encoded = requests.utils.quote(pid, safe="")
    raw = _bug_request(f"base_pid/{encoded}")
    return [_parse_bug(b) for b in raw]


def get_bugs_by_pid_version(pid: str, version: str) -> list[dict]:
    """Return normalized bugs affecting a specific PID + software version (all pages).
    Falls back to get_bugs_by_pid if the version endpoint returns nothing."""
    enc_pid = requests.utils.quote(pid, safe="")
    enc_ver = requests.utils.quote(version, safe="")
    raw = _bug_request(f"base_pid/{enc_pid}/affected_releases/{enc_ver}")
    if not raw:
        raw = _bug_request(f"base_pid/{enc_pid}")
    return [_parse_bug(b) for b in raw]


def get_bug_summary(pid: str, version: str = "") -> dict | None:
    """Convenience function for bulk lookups. Returns a flat summary dict or None on error."""
    try:
        bugs = get_bugs_by_pid_version(pid, version) if version else get_bugs_by_pid(pid)
    except Exception as exc:
        print(f"Bug summary failed for {pid}/{version}: {exc}", file=sys.stderr)
        return None

    open_bugs = [b for b in bugs if b.get("status") == "O"]
    threshold_bugs = [b for b in open_bugs if 0 < b.get("severity", 0) <= BUG_SEVERITY_THRESHOLD]

    return {
        "bug_compliance": _bug_compliance(bugs),
        "open_count":     len(open_bugs),
        "critical_count": len(threshold_bugs),
        "bug_ids":        ", ".join(b["bug_id"] for b in threshold_bugs if b["bug_id"]),
    }


def _print_bug_result(pid: str, version: str, bugs: list[dict]) -> None:
    """Print bug results in human-readable format."""
    compliance = _bug_compliance(bugs)
    open_bugs  = [b for b in bugs if b.get("status") == "O"]
    print(f"\n{'='*60}")
    print(f"PID      : {pid}")
    if version:
        print(f"Version  : {version}")
    print(f"Bugs     : {len(bugs)} total, {len(open_bugs)} open")
    print(f"Compliance: {compliance}")
    print(f"{'='*60}")
    for b in bugs:
        sev_label = b.get("severity_label") or str(b.get("severity", ""))
        status_label = b.get("status_label") or b.get("status", "")
        marker = " ★ OPEN" if b.get("status") == "O" else ""
        print(f"\n  [{sev_label}] {b['headline']}{marker}")
        print(f"  ID       : {b['bug_id']}")
        print(f"  Status   : {status_label}")
        if b.get("known_affected_releases"):
            print(f"  Affected : {b['known_affected_releases']}")
        if b.get("known_fixed_releases"):
            print(f"  Fixed In : {b['known_fixed_releases']}")
        if b.get("last_modified_date"):
            print(f"  Modified : {b['last_modified_date']}")
    if not bugs:
        print("\n  No bugs found — device is Compliant.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cisco Bug API v2.0 Tool")
    parser.add_argument("--pid", help="Single Base Product ID")
    parser.add_argument("--version", default="", help="Software version (optional — narrows results)")
    parser.add_argument("--batch-file", metavar="FILE",
                        help="Text file with one entry per line: 'pid' or 'pid:version'")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.batch_file:
        try:
            lines = Path(args.batch_file).read_text().splitlines()
        except OSError as e:
            print(f"Cannot read batch file: {e}", file=sys.stderr)
            sys.exit(1)

        results = []
        for raw_line in lines:
            raw_line = raw_line.strip()
            if not raw_line or raw_line.startswith("#"):
                continue
            if ":" in raw_line:
                pid, ver = raw_line.split(":", 1)
                pid = pid.strip(); ver = ver.strip()
            else:
                pid = raw_line; ver = ""
            if not pid:
                continue
            bugs = get_bugs_by_pid_version(pid, ver) if ver else get_bugs_by_pid(pid)
            if args.json:
                results.append({"pid": pid, "version": ver, "bugs": bugs,
                                 "compliance": _bug_compliance(bugs)})
            else:
                _print_bug_result(pid, ver, bugs)

        if args.json:
            print(json.dumps(results, indent=2))
        return

    if not args.pid:
        parser.error("--pid or --batch-file is required")

    bugs = get_bugs_by_pid_version(args.pid, args.version) if args.version else get_bugs_by_pid(args.pid)

    if args.json:
        print(json.dumps({
            "pid":        args.pid,
            "version":    args.version,
            "bugs":       bugs,
            "compliance": _bug_compliance(bugs),
        }, indent=2))
        return

    _print_bug_result(args.pid, args.version, bugs)


if __name__ == "__main__":
    main()
