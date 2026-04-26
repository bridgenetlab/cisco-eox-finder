"""
Cisco EOX V5 API Tool
Queries End-of-Life data by Product ID or Serial Number.
Credentials loaded from ../.env (CISCO_CLIENT_ID, CISCO_CLIENT_SECRET).

CLI Usage:
  python cisco_eox.py --pid WS-C2960X
  python cisco_eox.py --sn FHH12345678
  python cisco_eox.py --pid "WS-C2960*" --page 1
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, date
from pathlib import Path

import requests
from dotenv import load_dotenv

# Load .env from project root (one level up from tools/)
load_dotenv(Path(__file__).parent.parent / ".env")

CLIENT_ID = os.getenv("CISCO_CLIENT_ID")
CLIENT_SECRET = os.getenv("CISCO_CLIENT_SECRET")
TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
EOX_BASE_URL = "https://apix.cisco.com/supporttools/eox/rest/5"

# Compliance thresholds (days before last date of support). Override via EOX_WARN_DAYS env var.
WARN_DAYS = int(os.getenv("EOX_WARN_DAYS", "180"))

# In-memory token cache
_token_cache = {"access_token": None, "expires_at": 0}


def get_access_token() -> str:
    """Return a valid OAuth2 access token, refreshing if expired."""
    if _token_cache["access_token"] and time.time() < _token_cache["expires_at"] - 60:
        return _token_cache["access_token"]

    if not CLIENT_ID or not CLIENT_SECRET:
        raise ValueError(
            "CISCO_CLIENT_ID and CISCO_CLIENT_SECRET must be set in .env"
        )

    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache["access_token"] = data["access_token"]
    _token_cache["expires_at"] = time.time() + data.get("expires_in", 3600)
    return _token_cache["access_token"]


def _eox_request(endpoint: str, _retries: int = 3) -> dict:
    """Make authenticated GET request to EOX API, retrying on 429 with backoff."""
    url = f"{EOX_BASE_URL}/{endpoint}"
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
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()  # unreachable but satisfies type checkers


def _compliance_status(last_date_str: str) -> dict:
    """
    Compute compliance status from LastDateOfSupport string (YYYY-MM-DD or ' ').
    Returns dict with status, label, and days_remaining.
    """
    if not last_date_str or last_date_str.strip() == "":
        return {"status": "unknown", "label": "Unknown", "days_remaining": None}

    try:
        last_date = datetime.strptime(last_date_str, "%Y-%m-%d").date()
    except ValueError:
        return {"status": "unknown", "label": "Unknown", "days_remaining": None}

    today = date.today()
    days_remaining = (last_date - today).days

    if days_remaining < 0:
        return {"status": "noncompliant", "label": "Noncompliant", "days_remaining": days_remaining}
    elif days_remaining <= WARN_DAYS:
        return {"status": "warning", "label": "Compliant with Warning", "days_remaining": days_remaining}
    else:
        return {"status": "compliant", "label": "Compliant", "days_remaining": days_remaining}


def _parse_eox_record(record: dict) -> dict:
    """Flatten an EOXRecord dict into a clean result dict."""
    def date_val(obj):
        if isinstance(obj, dict):
            return obj.get("value", "")
        return obj or ""

    last_date_str = date_val(record.get("LastDateOfSupport", {}))
    compliance = _compliance_status(last_date_str)

    migration = record.get("EOXMigrationDetails", {})
    migration_pid = migration.get("MigrationProductId", "") if migration else ""
    migration_info = migration.get("MigrationInformation", "") if migration else ""
    migration_url = migration.get("MigrationProductInfoURL", "") if migration else ""

    return {
        "product_id": record.get("EOLProductID", ""),
        "product_name": record.get("ProductIDDescription", ""),
        "end_of_sale": date_val(record.get("EndOfSaleDate", {})),
        "end_of_sw_maintenance": date_val(record.get("EndOfSWMaintenanceReleases", {})),
        "end_of_security_support": date_val(record.get("EndOfSecurityVulSupportDate", {})),
        "end_of_routine_failure": date_val(record.get("EndOfRoutineFailureAnalysisDate", {})),
        "end_of_service_contract": date_val(record.get("EndOfServiceContractRenewal", {})),
        "last_date_of_support": last_date_str,
        "compliance": compliance,
        "migration_product_id": migration_pid,
        "migration_info": migration_info,
        "migration_url": migration_url,
        "bulletin_url": record.get("LinkToProductBulletinURL", ""),
    }


def query_by_product_id(pid: str, page: int = 1) -> dict:
    """
    Query EOX by Product ID (supports wildcards, comma-separated, up to 20).
    Returns dict with records list and pagination metadata.
    """
    endpoint = f"EOXByProductID/{page}/{requests.utils.quote(pid, safe=',*')}"
    raw = _eox_request(endpoint)

    eox_data = raw.get("EOXRecord", [])
    if isinstance(eox_data, dict):
        eox_data = [eox_data]

    pagination = {
        "page": raw.get("PaginationResponseRecord", {}).get("PageIndex", page),
        "last_page": raw.get("PaginationResponseRecord", {}).get("LastIndex", 1),
        "total_records": raw.get("PaginationResponseRecord", {}).get("TotalRecords", 0),
    }

    records = []
    for r in eox_data:
        # Check for error records
        if r.get("EOXError"):
            records.append({"error": r["EOXError"].get("ErrorDescription", "Unknown error"),
                            "query": r["EOXError"].get("ErrorDataValue", pid)})
        else:
            records.append(_parse_eox_record(r))

    return {"query_type": "product_id", "query": pid, "pagination": pagination, "records": records}


def query_by_serial_number(sn: str, page: int = 1) -> dict:
    """
    Query EOX by Serial Number (comma-separated, up to 20).
    Returns dict with records list and pagination metadata.
    """
    endpoint = f"EOXBySerialNumber/{page}/{requests.utils.quote(sn, safe=',')}"
    raw = _eox_request(endpoint)

    eox_data = raw.get("EOXRecord", [])
    if isinstance(eox_data, dict):
        eox_data = [eox_data]

    pagination = {
        "page": raw.get("PaginationResponseRecord", {}).get("PageIndex", page),
        "last_page": raw.get("PaginationResponseRecord", {}).get("LastIndex", 1),
        "total_records": raw.get("PaginationResponseRecord", {}).get("TotalRecords", 0),
    }

    records = []
    for r in eox_data:
        if r.get("EOXError"):
            records.append({"error": r["EOXError"].get("ErrorDescription", "Unknown error"),
                            "query": r["EOXError"].get("ErrorDataValue", sn)})
        else:
            records.append(_parse_eox_record(r))

    return {"query_type": "serial_number", "query": sn, "pagination": pagination, "records": records}


def query_all_pages_by_product_id(pid: str) -> dict:
    """
    Query all pages for a Product ID (useful for wildcard queries).
    Walks pages 1..last_page and returns all records combined.
    """
    first = query_by_product_id(pid, page=1)
    all_records = list(first["records"])
    last_page = first["pagination"]["last_page"]
    for page in range(2, last_page + 1):
        result = query_by_product_id(pid, page=page)
        all_records.extend(result["records"])
    return {
        "query_type": "product_id",
        "query": pid,
        "pagination": {**first["pagination"], "page": 1},
        "records": all_records,
    }


def main():
    parser = argparse.ArgumentParser(description="Cisco EOX V5 API Tool")
    parser.add_argument("--pid", help="Product ID (supports wildcards and comma-separated list)")
    parser.add_argument("--sn", help="Serial Number (comma-separated list)")
    parser.add_argument("--page", type=int, default=1, help="Page index (default: 1)")
    parser.add_argument("--all-pages", action="store_true", help="Fetch all pages (useful for wildcard queries)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if not args.pid and not args.sn:
        parser.error("Provide --pid or --sn (or both)")

    results = []
    if args.pid:
        if args.all_pages:
            results.append(query_all_pages_by_product_id(args.pid))
        else:
            results.append(query_by_product_id(args.pid, args.page))
    if args.sn:
        results.append(query_by_serial_number(args.sn, args.page))

    if args.json:
        print(json.dumps(results, indent=2))
        return

    for result in results:
        print(f"\n{'='*60}")
        print(f"Query Type : {result['query_type'].replace('_', ' ').title()}")
        print(f"Query      : {result['query']}")
        pg = result["pagination"]
        print(f"Page       : {pg['page']} of {pg['last_page']} ({pg['total_records']} total records)")
        print(f"{'='*60}")

        for rec in result["records"]:
            if "error" in rec:
                print(f"  ERROR [{rec['query']}]: {rec['error']}")
                continue

            compliance = rec["compliance"]
            status_str = compliance["label"]
            days = compliance["days_remaining"]
            days_str = f" ({days} days remaining)" if days is not None else ""

            print(f"\n  Product ID   : {rec['product_id']}")
            print(f"  Description  : {rec['product_name']}")
            print(f"  Compliance   : {status_str}{days_str}")
            print(f"  End of Sale  : {rec['end_of_sale'] or 'N/A'}")
            print(f"  End of SW    : {rec['end_of_sw_maintenance'] or 'N/A'}")
            print(f"  Last Support : {rec['last_date_of_support'] or 'N/A'}")
            if rec["migration_product_id"]:
                print(f"  Migrate To   : {rec['migration_product_id']} — {rec['migration_info']}")
            if rec["bulletin_url"]:
                print(f"  Bulletin     : {rec['bulletin_url']}")


if __name__ == "__main__":
    main()
