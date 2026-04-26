"""
Cisco PSIRT openVuln API Client
Queries security advisories by OS type and software version.
Reuses OAuth2 credentials and token cache from cisco_eox.

CLI Usage:
  python cisco_psirt.py --os-type iosxe --version 16.11.1
  python cisco_psirt.py --os-type iosxe --version 16.11.1 --json
  python cisco_psirt.py --os-type iosxe --version 16.11.1 --severity Critical
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

PSIRT_BASE_URL = "https://apix.cisco.com/security/advisories/v2/advisories"

OS_TYPES = {
    "ios":   "IOS",
    "iosxe": "IOS XE",
    "nxos":  "NX-OS",
    "asa":   "ASA",
    "ftd":   "FTD",
    "fxos":  "FXOS",
    "fmc":   "FMC",
}

# Configurable compliance threshold — advisories at or above this SIR level trigger Non-Compliant.
# Override via PSIRT_SEVERITY_THRESHOLD env var (choices: Critical, High, Medium, Low).
SEVERITY_THRESHOLD = os.getenv("PSIRT_SEVERITY_THRESHOLD", "Critical")

_SIR_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _psirt_request(path: str, _retries: int = 3) -> list[dict]:
    """Authenticated GET to the PSIRT openVuln API with exponential backoff on 429."""
    url = f"{PSIRT_BASE_URL}/{path}"
    for attempt in range(_retries + 1):
        resp = requests.get(
            url,
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
                # Surface the error but don't raise — caller treats empty list as Compliant
                print(
                    f"PSIRT {resp.status_code} for {path}: "
                    f"{body.get('errorMessage', resp.text)}",
                    file=sys.stderr,
                )
            except Exception:
                print(f"PSIRT {resp.status_code} for {path}: {resp.text}", file=sys.stderr)
            return []
        resp.raise_for_status()
        data = resp.json()
        # API may return a bare list or {"advisories": [...]}
        if isinstance(data, list):
            return data
        return data.get("advisories") or []
    resp.raise_for_status()
    return []


def _parse_psirt_advisory(adv: dict) -> dict:
    """Flatten one advisory entry from the PSIRT API response."""
    return {
        "advisory_id":     adv.get("advisoryId", ""),
        "title":           adv.get("advisoryTitle", ""),
        "sir":             adv.get("sir", ""),
        "cvss_score":      adv.get("cvssBaseScore", ""),
        "cves":            adv.get("cves") or [],
        "bug_ids":         adv.get("bugIDs") or [],
        "first_published": adv.get("firstPublished", ""),
        "publication_url": adv.get("publicationUrl", ""),
    }


def _psirt_compliance(advisories: list[dict]) -> str:
    """
    Returns 'Non-Compliant' if any advisory meets or exceeds SEVERITY_THRESHOLD.
    Returns 'Compliant' otherwise (including empty advisory list).
    'NA' is never returned here — callers set that when no version is provided.
    """
    threshold_rank = _SIR_RANK.get(SEVERITY_THRESHOLD.lower(), 4)
    for adv in advisories:
        rank = _SIR_RANK.get((adv.get("sir") or "").lower(), 0)
        if rank >= threshold_rank:
            return "Non-Compliant"
    return "Compliant"


def query_psirt_by_version(os_type: str, version: str) -> dict:
    """
    Query PSIRT advisories for a specific OS type and software version.
    Returns dict with advisories list, compliance status, and any error.
    """
    if os_type not in OS_TYPES:
        return {
            "os_type": os_type,
            "version": version,
            "advisories": [],
            "compliance": "NA",
            "error": f"Unknown OS type '{os_type}'. Valid types: {', '.join(OS_TYPES)}",
        }

    path = f"{os_type}/{requests.utils.quote(version, safe='')}"
    raw = _psirt_request(path)
    advisories = [_parse_psirt_advisory(a) for a in raw]

    return {
        "os_type":    os_type,
        "version":    version,
        "advisories": advisories,
        "compliance": _psirt_compliance(advisories),
        "error":      None,
    }


def get_psirt_summary(os_type: str, version: str) -> dict | None:
    """
    Convenience function for bulk lookups.
    Returns a flat summary dict or None on error.
    """
    if not os_type or not version:
        return None
    result = query_psirt_by_version(os_type, version)
    if result.get("error"):
        return None

    threshold_rank = _SIR_RANK.get(SEVERITY_THRESHOLD.lower(), 4)
    critical_advs = [
        a for a in result["advisories"]
        if _SIR_RANK.get((a.get("sir") or "").lower(), 0) >= threshold_rank
    ]

    return {
        "compliance":     result["compliance"],
        "critical_count": len(critical_advs),
        "advisory_ids":   ", ".join(a["advisory_id"] for a in critical_advs),
        "cves":           ", ".join(cve for a in critical_advs for cve in (a.get("cves") or [])),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Cisco PSIRT openVuln Security Advisory Tool")
    parser.add_argument("--os-type", required=True, choices=list(OS_TYPES.keys()),
                        metavar="OS_TYPE",
                        help=f"OS type ({', '.join(OS_TYPES)})")
    parser.add_argument("--version", required=True, help="Software version string (e.g. 16.11.1)")
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low"],
                        help="Filter displayed advisories to this SIR level only")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    result = query_psirt_by_version(args.os_type, args.version)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    advisories = result.get("advisories", [])
    if args.severity:
        advisories = [a for a in advisories if a["sir"].lower() == args.severity.lower()]

    print(f"\n{'='*60}")
    print(f"OS Type    : {OS_TYPES.get(args.os_type, args.os_type)}")
    print(f"Version    : {result['version']}")
    print(f"Compliance : {result['compliance']}")
    print(f"Advisories : {len(result['advisories'])} total"
          + (f" ({len(advisories)} shown after filter)" if args.severity else ""))
    print(f"{'='*60}")

    for adv in advisories:
        print(f"\n  [{adv['sir']}] {adv['title']}")
        print(f"  ID     : {adv['advisory_id']}")
        print(f"  CVEs   : {', '.join(adv['cves']) or 'N/A'}")
        print(f"  CVSS   : {adv['cvss_score'] or 'N/A'}")
        print(f"  Date   : {adv['first_published'] or 'N/A'}")
        if adv["publication_url"]:
            print(f"  URL    : {adv['publication_url']}")

    if not advisories and not result.get("error"):
        print("\n  No advisories found — device is Compliant.")


if __name__ == "__main__":
    main()
