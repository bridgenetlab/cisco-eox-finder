# Workflow: Config Diff Risk Analyzer

## Objective

Compare two Cisco device configurations (startup vs running, baseline vs proposed change)
and classify every difference by risk level so you can immediately identify which changes
could cause outages, security regressions, or unexpected network behavior.

---

## Risk Levels

| Level | Score Weight | Typical Triggers |
|---|---|---|
| `Critical` | 10 | ACL removal, AAA removed, routing protocol removed, STP disabled, crypto removed, default route deleted, `permit any any` added |
| `High` | 5 | Interface shutdown, SSH disabled, static route removed, VLAN removed, `no shutdown` removed, BPDU guard removed |
| `Medium` | 2 | IP address change, QoS policy change, VLAN assignment change, NTP change, trunk VLAN change |
| `Low` | 1 | Description change, banner change, SNMP contact/location change |

**Risk Score** = `(critical × 10) + (high × 5) + (medium × 2) + (low × 1)`

A score ≥ 20 is Critical, ≥ 10 is High, ≥ 3 is Medium, < 3 is Low.

---

## Required Inputs

| Input | Required | Notes |
|---|---|---|
| Reference Config | Yes | Baseline / startup configuration |
| Current Config | Yes | Running / proposed configuration |
| Minimum Risk Level | No | Filter display to `critical`, `high`, `medium`, `low`, or `info` (default: show all) |

---

## Tools

| Tool | Purpose |
|---|---|
| `tools/cisco_config_diff.py` | Diff + risk analysis engine — no API credentials needed |
| `tools/cisco_eox_webapp.py` | Flask web app — Config Diff tab |

No Cisco API credentials are required. This is a fully offline local analysis.

---

## Steps

### CLI

```bash
cd tools

# Compare two config files
python cisco_config_diff.py --reference startup.cfg --current running.cfg

# Show only high-risk changes and above
python cisco_config_diff.py --reference startup.cfg --current running.cfg --min-risk high

# Raw JSON output (for integration with other tools)
python cisco_config_diff.py --reference startup.cfg --current running.cfg --json

# No terminal colours (for piping/logging)
python cisco_config_diff.py --reference startup.cfg --current running.cfg --no-color
```

### Web App

1. Start the app: `cd tools && python cisco_eox_webapp.py`
2. Open `http://localhost:5001`
3. Click the **Config Diff** tab
4. Paste or upload the **Reference Config** (startup / baseline) in the left pane
5. Paste or upload the **Current Config** (running / proposed) in the right pane
6. Optionally: set minimum risk level to focus on high-priority changes only
7. Click **Analyze Risk**
8. Review the risk summary bar (Risk Score + pill counts per level)
9. Scroll the annotated diff table — each changed line shows its risk badge and reason
10. Click **⎙ Download HTML Report** to save a self-contained report

**Load Sample** buttons pre-load a realistic example showing an ACL weakening and IP change.

---

## Output Fields (per changed line)

| Field | Description |
|---|---|
| `action` | `add` (in current, not reference) / `remove` (in reference, not current) / `context` / `separator` |
| `ref_line_no` | Line number in reference config |
| `cur_line_no` | Line number in current config |
| `content` | The config line text |
| `risk_level` | `critical`, `high`, `medium`, `low`, or `info` |
| `risk_reason` | Human-readable explanation of the risk |

---

## Risk Rule Categories

### Critical — Immediate action required
- **AAA removal**: `no aaa`, removing `aaa authentication/authorization` — loss of centralized auth
- **ACL removal**: `no ip access-list`, `no access-list` — traffic filtering bypassed
- **Crypto removal**: `no crypto` — VPN tunnels drop, data unencrypted in transit
- **Routing protocol removal**: `no router ospf/bgp/eigrp/isis` — routing table collapse
- **Default route removed**: connectivity to upstream networks lost
- **STP disabled**: spanning-tree loops can bring down entire VLAN
- **Unrestricted permit**: `permit any any` or `permit ip any any` — complete firewall bypass

### High — Review before deploying
- **Interface shutdown**: port going down — hosts/links lose connectivity
- **SSH disabled**: management access cut
- **Static route removed**: specific destinations unreachable
- **VLAN removed**: all hosts in that VLAN lose network access
- **`no shutdown` removed**: interface may revert to shutdown

### Medium — Test in staging first
- IP address change, QoS policy change, VLAN reassignment, NTP server change, trunk VLAN list change

### Low — Safe, cosmetic
- Description, banner, SNMP contact/location, hostname

---

## Edge Cases

| Situation | Behaviour |
|---|---|
| Identical configs | No changes returned; report shows "configurations are identical" |
| Very large configs (3000+ lines) | Diff is computed with SequenceMatcher; may take 1–2 seconds |
| NX-OS / ASA syntax | Most rules apply; some IOS-specific patterns may not match NX-OS syntax |
| Partial configs / snippets | Supported — tool does not require complete `show running` output |
| Configs with passwords | No API calls made; content never leaves the browser in web mode |
| `no` command chains | Rules match on both `no <feature>` additions and `<feature>` removals |

---

## Integration Notes

The `analyze_diff()` function is importable from other Python scripts:

```python
from cisco_config_diff import analyze_diff

with open("startup.cfg") as f:
    ref = f.readlines()
with open("running.cfg") as f:
    cur = f.readlines()

result = analyze_diff(ref, cur)
print(result["risk_score"])            # integer
print(result["summary"]["critical"])   # count
for change in result["changes"]:
    if change["risk_level"] == "critical":
        print(change["content"], "→", change["risk_reason"])
```

---

## Self-Improvement Log

_Append discoveries here — new risk patterns found, false positives to suppress, platform-specific syntax quirks, etc._
