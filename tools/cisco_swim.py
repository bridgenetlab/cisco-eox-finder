"""
Cisco Software Suggestion API (SWIM) Client
Queries recommended ("golden") software releases by Product ID.
Reuses OAuth2 credentials and token cache from cisco_eox.

CLI Usage:
  python cisco_swim.py --pid ASR-903
  python cisco_swim.py --pid WS-C3850-24T --json
  python cisco_swim.py --pid ASR-903 --all-pages
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from cisco_eox import get_access_token

SWIM_BASE_URL = "https://apix.cisco.com/software/suggestion/v2/suggestions/software/productIds"


def _swim_request(pid: str, page_index: int = 1, _retries: int = 3) -> dict:
    """Authenticated GET to the SWIM API with exponential backoff on 429."""
    encoded = requests.utils.quote(pid, safe="")
    url = f"{SWIM_BASE_URL}/{encoded}"
    params = {"pageIndex": page_index} if page_index > 1 else None
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
                raise ValueError(body.get("errorDescription", resp.text))
            except (ValueError, KeyError):
                raise
            except Exception:
                resp.raise_for_status()
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()


def _parse_swim_image(image: dict) -> dict:
    """Flatten one image entry from a suggestion."""
    return {
        "name":           image.get("imageName", ""),
        "size_bytes":     image.get("imageSize", ""),
        "feature_set":    image.get("featureSet", ""),
        "description":    image.get("description", ""),
        "required_dram":  image.get("requiredDRAM", ""),
        "required_flash": image.get("requiredFlash", ""),
    }


def _parse_swim_suggestion(suggestion: dict) -> dict:
    """Flatten one suggestion entry from a product."""
    error_detail = suggestion.get("errorDetailsResponse")
    error_msg = None
    if error_detail:
        if isinstance(error_detail, dict):
            error_msg = error_detail.get("errorDescription") or str(error_detail)
        else:
            error_msg = str(error_detail)

    images = [_parse_swim_image(img) for img in suggestion.get("images") or []]

    return {
        "is_suggested":   bool(suggestion.get("isSuggested")),
        "release_format": suggestion.get("releaseFormat1", ""),
        "release_date":   suggestion.get("releaseDate", ""),
        "release_train":  suggestion.get("releaseTrain", ""),
        "lifecycle":      suggestion.get("releaseLifeCycle", ""),
        "display_name":   suggestion.get("relDispName", ""),
        "train_display":  suggestion.get("trainDispName", ""),
        "images":         images,
        "error":          error_msg,
    }


def _parse_swim_product(product: dict) -> dict:
    """Flatten one productList entry."""
    return {
        "base_pid":      product.get("basePID", ""),
        "mdf_id":        product.get("mdfId", ""),
        "product_name":  product.get("productName", ""),
        "software_type": product.get("softwareType", ""),
        "suggestions":   [_parse_swim_suggestion(s) for s in product.get("suggestions") or []],
    }


def _swim_compliance(current_version: str, suggested_release: str) -> str:
    """
    Compare a device's running version against the SWIM suggested release.
    Returns 'Compliant', 'Non-Compliant', or 'Unknown'.
    """
    cv = (current_version or "").strip()
    sr = (suggested_release or "").strip()
    if not cv or not sr:
        return "Unknown"
    return "Compliant" if cv.lower() == sr.lower() else "Non-Compliant"


def query_swim_by_pid(pid: str, page_index: int = 1) -> dict:
    """
    Query SWIM by a single Product ID.
    Returns dict with products list and pagination metadata.
    """
    try:
        raw = _swim_request(pid, page_index=page_index)
    except ValueError as exc:
        return {"query": pid, "pagination": {}, "products": [], "error": str(exc)}
    except requests.HTTPError as exc:
        return {"query": pid, "pagination": {}, "products": [], "error": str(exc)}

    pg_rec = raw.get("paginationResponseRecord") or {}
    pagination = {
        "page_index":    pg_rec.get("pageIndex", page_index),
        "last_index":    pg_rec.get("lastIndex", 1),
        "total_records": pg_rec.get("totalRecords", 0),
        "page_records":  pg_rec.get("pageRecords", 0),
    }

    products = [_parse_swim_product(p) for p in raw.get("productList") or []]

    return {"query": pid, "pagination": pagination, "products": products, "error": None}


def query_all_pages_swim_by_pid(pid: str) -> dict:
    """
    Fetch all pages for a Product ID query and return combined products.
    """
    first = query_swim_by_pid(pid, page_index=1)
    if first.get("error") or not first["pagination"]:
        return first

    all_products = list(first["products"])
    last_index = first["pagination"].get("last_index", 1)
    for page in range(2, last_index + 1):
        result = query_swim_by_pid(pid, page_index=page)
        all_products.extend(result["products"])

    return {**first, "products": all_products}


def get_suggested_release(pid: str) -> dict | None:
    """
    Convenience function for bulk lookups.
    Returns {'suggested_release': str, 'lifecycle': str} for the first
    isSuggested=True suggestion, or None if unavailable.
    """
    result = query_swim_by_pid(pid)
    if result.get("error"):
        return None
    for product in result.get("products", []):
        for suggestion in product.get("suggestions", []):
            if suggestion.get("is_suggested") and not suggestion.get("error"):
                return {
                    "suggested_release": suggestion["release_format"],
                    "lifecycle":         suggestion["lifecycle"],
                }
    return None


def _print_swim_result(result: dict) -> None:
    """Print a single SWIM result in human-readable format."""
    if result.get("error"):
        print(f"ERROR: {result['error']}")
        return
    pg = result["pagination"]
    print(f"\n{'='*60}")
    print(f"Query : {result['query']}")
    print(f"Page  : {pg.get('page_index', 1)} of {pg.get('last_index', 1)} "
          f"({pg.get('total_records', 0)} total records)")
    print(f"{'='*60}")
    for product in result.get("products", []):
        print(f"\n  PID          : {product['base_pid']}")
        print(f"  Product      : {product['product_name']}")
        print(f"  Software Type: {product['software_type']}")
        for s in product.get("suggestions", []):
            if s.get("error"):
                print(f"\n    [ERROR] {s['error']}")
                continue
            marker = " ★ SUGGESTED" if s["is_suggested"] else ""
            print(f"\n    Release : {s['display_name']}{marker}")
            print(f"    Train   : {s['train_display']}")
            print(f"    Date    : {s['release_date'] or 'N/A'}")
            print(f"    Lifecycle: {s['lifecycle'] or 'N/A'}")
            for img in s.get("images", []):
                size_mb = round(int(img["size_bytes"]) / 1_048_576, 1) if img["size_bytes"] else "?"
                print(f"      Image : {img['name']}  ({size_mb} MB)  [{img['feature_set']}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cisco SWIM Software Suggestion Tool")
    parser.add_argument("--pid", help="Single Product ID (no wildcards or commas)")
    parser.add_argument("--batch-file", metavar="FILE",
                        help="Text file with one PID per line")
    parser.add_argument("--page", type=int, default=1, help="Page index (default: 1)")
    parser.add_argument("--all-pages", action="store_true", help="Fetch all pages")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.batch_file:
        try:
            lines = Path(args.batch_file).read_text().splitlines()
        except OSError as e:
            print(f"Cannot read batch file: {e}", file=sys.stderr)
            sys.exit(1)

        pids = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        results = []
        for pid in pids:
            if "*" in pid or "," in pid:
                print(f"Skipping '{pid}' — SWIM does not support wildcards or commas", file=sys.stderr)
                continue
            r = query_all_pages_swim_by_pid(pid) if args.all_pages else query_swim_by_pid(pid, args.page)
            results.append(r)

        if args.json:
            print(json.dumps(results, indent=2))
            return
        for r in results:
            _print_swim_result(r)
        return

    if not args.pid:
        parser.error("--pid or --batch-file is required")

    if "*" in args.pid or "," in args.pid:
        parser.error("SWIM API requires a single exact PID — wildcards and comma-separated lists are not supported")

    result = query_all_pages_swim_by_pid(args.pid) if args.all_pages else query_swim_by_pid(args.pid, args.page)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    _print_swim_result(result)


if __name__ == "__main__":
    main()
