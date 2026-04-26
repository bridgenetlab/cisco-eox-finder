"""
Cisco Serial Number to Information (SN2INFO) v2 API Client
Resolves serial numbers to Product IDs and retrieves contract coverage status
in a single API call via the coverage/summary endpoint.
Reuses OAuth2 credentials and token cache from cisco_eox.

CLI Usage:
  python cisco_sn2info.py --sn FOC10220LK9
  python cisco_sn2info.py --sn "SN1,SN2,SN3" --json
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from cisco_eox import get_access_token

SN2INFO_BASE_URL = "https://apix.cisco.com/sn2info/v2"


def _sn2info_request(path: str, page_index: int = 1, _retries: int = 3) -> dict:
    """Authenticated GET to the SN2INFO API with exponential backoff on 429."""
    url = f"{SN2INFO_BASE_URL}/{path}"
    params = {"page_index": page_index} if page_index > 1 else None
    for attempt in range(_retries + 1):
        resp = requests.get(
            url,
            params=params,
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
                    f"SN2INFO {resp.status_code} for {path}: "
                    f"{body.get('errorMessage', resp.text)}",
                    file=sys.stderr,
                )
            except Exception:
                print(f"SN2INFO {resp.status_code} for {path}: {resp.text}", file=sys.stderr)
            return {}
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()
    return {}


def _parse_sn_coverage(sn_data: dict) -> dict:
    """Flatten one serial_numbers entry from the coverage/summary response."""
    base_pids = sn_data.get("base_pid_list") or []
    ord_pids  = sn_data.get("orderable_pid_list") or []
    is_covered = (sn_data.get("is_covered") or "").upper()
    return {
        "coverage_status":   "Active" if is_covered == "YES" else ("Inactive" if is_covered == "NO" else ""),
        "coverage_end_date": sn_data.get("coverage_end_date", ""),
        "contract_number":   sn_data.get("service_contract_number", ""),
        "service_level":     sn_data.get("service_line_descr", ""),
        "base_pid":          base_pids[0].get("base_pid", "") if base_pids else "",
        "orderable_pid":     ord_pids[0].get("orderable_pid", "") if ord_pids else "",
    }


def get_coverage_summary(sns: list[str]) -> dict[str, dict]:
    """
    Coverage + PID lookup for a batch of serial numbers.
    SNs are passed comma-separated in the URL path.
    Returns {SN_UPPER: {coverage_status, coverage_end_date, contract_number,
                        service_level, base_pid, orderable_pid}}.
    """
    if not sns:
        return {}

    encoded = requests.utils.quote(",".join(sns), safe=",")
    path = f"coverage/summary/serial_numbers/{encoded}"
    lookup: dict[str, dict] = {}

    page = 1
    while True:
        raw = _sn2info_request(path, page_index=page)
        if not raw:
            break
        for sn_data in raw.get("serial_numbers") or []:
            sn = (sn_data.get("sr_no") or "").upper()
            if sn:
                lookup[sn] = _parse_sn_coverage(sn_data)
        pg = raw.get("pagination_response_record") or {}
        if page >= int(pg.get("last_index", 1)):
            break
        page += 1

    return lookup


def get_pids_from_sns(sns: list[str]) -> dict[str, str]:
    """
    Convenience function: resolve serial numbers to orderable PIDs.
    Returns {SN_UPPER: orderable_pid}.
    """
    coverage = get_coverage_summary(sns)
    return {
        sn: data.get("orderable_pid") or data.get("base_pid", "")
        for sn, data in coverage.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cisco SN2INFO v2 — Serial Number to PID and Coverage Status"
    )
    parser.add_argument(
        "--sn", required=True,
        help="Serial number(s) — comma-separated for multiple (e.g. SN1,SN2)"
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    sns = [s.strip() for s in args.sn.split(",") if s.strip()]
    result = get_coverage_summary(sns)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if not result:
        print("No results found.")
        return

    print(f"\n{'='*60}")
    print(f"Serial Numbers : {len(sns)} queried, {len(result)} matched")
    print(f"{'='*60}")

    for sn, data in result.items():
        pid = data.get("orderable_pid") or data.get("base_pid") or "N/A"
        print(f"\n  SN             : {sn}")
        print(f"  PID            : {pid}")
        print(f"  Coverage       : {data.get('coverage_status') or 'Unknown'}")
        print(f"  Coverage End   : {data.get('coverage_end_date') or 'N/A'}")
        print(f"  Contract No.   : {data.get('contract_number') or 'N/A'}")
        print(f"  Service Level  : {data.get('service_level') or 'N/A'}")


if __name__ == "__main__":
    main()
