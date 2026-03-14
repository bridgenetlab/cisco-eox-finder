# Workflow: Cisco EOX Lookup

## Objective
Retrieve End-of-Life (EOX) data from the Cisco EOX V5 API for one or more devices, and surface their compliance status (Compliant / Compliant with Warning / Noncompliant).

## Required Inputs
- **Product ID** (PID) — e.g. `WS-C2960X-24TS-L`, or wildcard `WS-C2960*`, or comma-separated list (max 20)
- **Serial Number** (SN) — e.g. `FHH12345678`, or comma-separated list (max 20)
- At least one of PID or SN must be provided. Both can be used together.

## Credentials
Stored in `.env` at project root:
- `CISCO_CLIENT_ID` — OAuth 2.0 client ID
- `CISCO_CLIENT_SECRET` — OAuth 2.0 client secret

## Tools
| Tool | Purpose |
|------|---------|
| `tools/cisco_eox.py` | Core API tool — auth, query, parse, compliance |
| `tools/cisco_eox_webapp.py` | Flask web UI for interactive use |

## Steps

### CLI (scripted / agent use)
```bash
cd tools
python cisco_eox.py --pid WS-C2960X-24TS-L
python cisco_eox.py --sn FHH12345678
python cisco_eox.py --pid WS-C2960X --json        # raw JSON output
python cisco_eox.py --pid "WS-C2960*" --page 2    # paginate wildcard results
python cisco_eox.py --pid WS-C2960X --sn FHH123   # both at once
```

### Web App (interactive use)
```bash
cd tools
python cisco_eox_webapp.py
# Open http://localhost:5001
```

## Expected Output (per record)
| Field | Description |
|-------|-------------|
| `product_id` | EOL Product ID |
| `product_name` | Product description |
| `end_of_sale` | End of Sale date |
| `end_of_sw_maintenance` | End of SW Maintenance date |
| `end_of_security_support` | End of Security Vulnerability Support date |
| `end_of_service_contract` | End of Service Contract Renewal date |
| `last_date_of_support` | Last Date of Support (LDoS) |
| `compliance.status` | `compliant` / `warning` / `noncompliant` / `unknown` |
| `compliance.label` | Human-readable compliance label |
| `compliance.days_remaining` | Days until (or since) LDoS |
| `migration_product_id` | Recommended replacement PID |
| `migration_info` | Migration notes |
| `bulletin_url` | Link to Cisco EOL bulletin |

## Compliance Rules
| Status | Condition |
|--------|-----------|
| **Noncompliant** | `LastDateOfSupport` < today |
| **Compliant with Warning** | 0 – 180 days until `LastDateOfSupport` |
| **Compliant** | > 180 days until `LastDateOfSupport` |
| **Unknown** | Date missing or unparseable |

## Pagination
- Results are paginated (up to 50 per page).
- If `pagination.last_page > 1`, use `--page N` to retrieve subsequent pages.
- Wildcard PIDs (`WS-C2960*`) typically return multiple pages.

## Edge Cases
| Situation | Behaviour |
|-----------|-----------|
| Invalid PID/SN | API returns `EOXError`; tool surfaces error per record |
| No EOX record exists | `EOXError` with "No Record Found" |
| Wildcard with many results | Pagination required — check `last_page` |
| Missing `LastDateOfSupport` | Compliance set to `unknown` |
| Token expiry | Token auto-refreshed on next call |
| Rate limiting (HTTP 429) | Script raises exception — wait before retrying |

## Known Constraints
- Max 20 PIDs or SNs per request (API limit).
- Wildcard queries require at least 3 characters before the `*`.
- OAuth token valid for ~1 hour; tool caches it in memory per process.

## Self-Improvement Log
- _(Update this section when new constraints, rate limits, or API quirks are discovered)_
