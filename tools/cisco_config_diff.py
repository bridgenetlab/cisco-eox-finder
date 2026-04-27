"""
Cisco Config Diff Risk Analyzer
Compares two IOS/NX-OS/ASA configuration blocks and flags changes that could
cause network misbehavior, outages, or security regressions.

CLI Usage:
  python cisco_config_diff.py --reference startup.cfg --current running.cfg
  python cisco_config_diff.py --reference startup.cfg --current running.cfg --min-risk medium
  python cisco_config_diff.py --reference startup.cfg --current running.cfg --json
"""

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

# Risk level ordering (higher = more severe)
RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

RISK_LABELS = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}

# ── Risk rules ────────────────────────────────────────────────────────────────
# Each rule: (regex_pattern, risk_level, human_reason)
# ADD_RULES   — applied to lines that appear in current but NOT in reference (line added)
# REMOVE_RULES — applied to lines that are in reference but NOT in current (line removed)

ADD_RULES = [
    # Authentication / Authorization
    (r"^\s*no\s+aaa\b",                          "critical", "AAA authentication removed — management access risk"),
    (r"^\s*no\s+service\s+password-encryption\b","critical", "Plaintext passwords now allowed in config"),
    (r"^\s*no\s+ip\s+ssh\b",                     "high",     "SSH management access disabled"),
    (r"^\s*no\s+tacacs-server\b",                "high",     "TACACS+ server removed"),
    (r"^\s*no\s+radius-server\b",                "high",     "RADIUS server removed"),

    # Access control / Firewall
    (r"^\s*no\s+ip\s+access-list\b",             "critical", "Named ACL removed — traffic filtering lost"),
    (r"^\s*no\s+access-list\b",                   "critical", "ACL removed — traffic filtering lost"),
    (r"\bpermit\s+any\s+any\b",                  "critical", "Unrestricted permit rule — security bypass"),
    (r"\bpermit\s+ip\s+any\s+any\b",             "critical", "Unrestricted IP permit — security bypass"),
    (r"^\s*no\s+ip\s+inspect\b",                 "high",     "CBAC/firewall inspection removed"),
    (r"^\s*no\s+zone-member\s+security\b",       "high",     "ZBF zone membership removed"),

    # Encryption / VPN
    (r"^\s*no\s+crypto\b",                        "critical", "Crypto/VPN configuration removed"),
    (r"^\s*no\s+tunnel\s+protection\b",           "high",     "Tunnel encryption removed"),

    # Routing
    (r"^\s*no\s+router\s+\w",                    "critical", "Routing protocol instance removed"),
    (r"^\s*no\s+ip\s+route\s+0\.0\.0\.0\b",     "critical", "Default route removed — connectivity loss likely"),
    (r"^\s*ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0\b","high",  "Default route added or changed"),
    (r"^\s*no\s+ip\s+route\b",                   "high",     "Static route removed"),
    (r"^\s*no\s+ipv6\s+route\b",                 "high",     "IPv6 static route removed"),
    (r"^\s*no\s+network\b",                       "high",     "Routing network statement removed"),
    (r"^\s*no\s+redistribute\b",                  "medium",   "Route redistribution removed"),
    (r"^\s*no\s+default-information\b",           "medium",   "Default route origination removed"),

    # Spanning Tree
    (r"^\s*no\s+spanning-tree\b",                "critical", "STP disabled — broadcast storm / loop risk"),
    (r"^\s*spanning-tree\s+portfast\b",          "medium",   "PortFast enabled — STP bypass on port"),
    (r"^\s*spanning-tree\s+bpduguard\s+disable\b","medium",  "BPDU guard disabled on port"),

    # Interface state
    (r"^\s*shutdown\b",                           "high",     "Interface shutdown — connectivity loss"),
    (r"^\s*no\s+no\s+shutdown\b",                "high",     "Interface shutdown state change"),

    # VLANs / Switching
    (r"^\s*no\s+vlan\b",                          "high",     "VLAN removed — hosts may lose connectivity"),
    (r"^\s*switchport\s+access\s+vlan\b",        "medium",   "Access VLAN assignment changed"),
    (r"^\s*switchport\s+trunk\s+allowed\s+vlan\b","medium",  "Trunk allowed VLANs changed"),
    (r"^\s*switchport\s+mode\b",                 "medium",   "Switchport mode changed (access/trunk)"),
    (r"^\s*no\s+switchport\s+trunk\b",           "medium",   "Trunk configuration removed"),

    # IP addressing
    (r"^\s*ip\s+address\b",                       "medium",   "IP address added or changed"),
    (r"^\s*no\s+ip\s+address\b",                 "medium",   "IP address removed"),
    (r"^\s*ipv6\s+address\b",                    "medium",   "IPv6 address changed"),

    # QoS
    (r"^\s*no\s+service-policy\b",               "medium",   "QoS policy removed from interface"),
    (r"^\s*service-policy\b",                    "medium",   "QoS policy applied or changed"),

    # NTP / Time
    (r"^\s*no\s+ntp\b",                           "medium",   "NTP removed — clock sync disrupted"),
    (r"^\s*ntp\s+server\b",                       "medium",   "NTP server changed"),

    # Logging / Audit
    (r"^\s*no\s+logging\b",                       "medium",   "Logging destination removed — audit trail gap"),
    (r"^\s*logging\s+(host|server)\b",            "low",      "Syslog destination changed"),

    # Management cosmetics (low risk)
    (r"^\s*description\b",                        "low",      "Interface description change"),
    (r"^\s*banner\b",                             "low",      "Login/MOTD banner changed"),
    (r"^\s*snmp-server\s+(contact|location)\b",  "low",      "SNMP contact or location changed"),
    (r"^\s*hostname\b",                           "low",      "Hostname changed"),
]

REMOVE_RULES = [
    # Authentication / Authorization
    (r"^\s*aaa\s+(authentication|authorization|accounting)\b","critical", "AAA policy removed — auth enforcement lost"),
    (r"^\s*service\s+password-encryption\b",      "critical", "Password encryption removed"),
    (r"^\s*tacacs-server\b",                       "high",     "TACACS+ server definition removed"),
    (r"^\s*radius-server\b",                       "high",     "RADIUS server definition removed"),
    (r"^\s*ip\s+ssh\s+version\b",                 "medium",   "SSH version constraint removed"),

    # Access control / Firewall
    (r"^\s*ip\s+access-list\b",                  "critical", "Named ACL definition removed"),
    (r"^\s*access-list\b",                         "critical", "ACL definition removed"),
    (r"^\s* deny\b",                               "high",     "Deny rule removed — traffic may now pass"),
    (r"^\s*ip\s+inspect\b",                       "high",     "CBAC inspection rule removed"),
    (r"^\s*zone-pair\s+security\b",               "high",     "ZBF zone-pair removed"),

    # Encryption / VPN
    (r"^\s*crypto\s+(map|isakmp|ipsec|keyring|pki|ikev[12])\b","critical","Crypto/VPN config removed"),
    (r"^\s*tunnel\s+protection\b",                "high",     "Tunnel encryption removed"),

    # Routing
    (r"^\s*router\s+(ospf|bgp|eigrp|isis|rip|lisp)\b","critical","Routing protocol removed"),
    (r"^\s*ip\s+route\b",                         "high",     "Static route removed"),
    (r"^\s*ipv6\s+route\b",                       "high",     "IPv6 static route removed"),
    (r"^\s*network\b",                             "medium",   "Routing network statement removed"),
    (r"^\s*neighbor\b",                            "medium",   "BGP/routing neighbor removed"),
    (r"^\s*redistribute\b",                        "medium",   "Route redistribution removed"),

    # Spanning Tree
    (r"^\s*spanning-tree\b",                      "high",     "STP configuration removed"),
    (r"^\s*spanning-tree\s+bpduguard\s+enable\b", "high",     "BPDU guard removed — rogue switch risk"),

    # Interface state
    (r"^\s*no\s+shutdown\b",                      "high",     "Interface may revert to shutdown state"),

    # VLANs / Switching
    (r"^\s*vlan\b",                                "high",     "VLAN definition removed"),
    (r"^\s*switchport\s+access\s+vlan\b",        "medium",   "Access VLAN assignment removed"),
    (r"^\s*switchport\s+trunk\s+allowed\b",      "medium",   "Trunk VLAN list changed"),

    # IP addressing
    (r"^\s*ip\s+address\b",                       "medium",   "IP address configuration removed"),
    (r"^\s*ipv6\s+address\b",                    "medium",   "IPv6 address removed"),

    # QoS
    (r"^\s*service-policy\b",                    "medium",   "QoS policy removed"),
    (r"^\s*policy-map\b",                         "medium",   "QoS policy-map definition removed"),
    (r"^\s*class-map\b",                          "low",      "QoS class-map removed"),

    # NTP / Logging
    (r"^\s*ntp\b",                                "medium",   "NTP configuration removed"),
    (r"^\s*logging\b",                            "medium",   "Logging configuration removed"),

    # Management cosmetics
    (r"^\s*description\b",                        "low",      "Description removed"),
    (r"^\s*banner\b",                             "low",      "Banner removed"),
    (r"^\s*snmp-server\s+(contact|location)\b",  "low",      "SNMP metadata removed"),
]


def _classify_change(line: str, action: str) -> tuple[str, str]:
    """
    Classify a single changed config line.
    action: 'add' (line in current, not reference) or 'remove' (line in reference, not current)
    Returns (risk_level, risk_reason). Defaults to ('info', '') if no rule matches.
    """
    rules = ADD_RULES if action == "add" else REMOVE_RULES
    for pattern, level, reason in rules:
        if re.search(pattern, line, re.IGNORECASE):
            return level, reason
    return "info", ""


def analyze_diff(reference_lines: list[str], current_lines: list[str]) -> dict:
    """
    Diff reference_lines against current_lines and return annotated changes with risk levels.

    Returns:
        {
          "changes": [
            {
              "ref_line_no":  int | None,
              "cur_line_no":  int | None,
              "action":       "add" | "remove" | "context",
              "content":      str,
              "risk_level":   str,   # 'critical'|'high'|'medium'|'low'|'info'
              "risk_reason":  str,
            }, ...
          ],
          "summary": {
            "total_changes": int,
            "lines_added":   int,
            "lines_removed": int,
            "critical": int, "high": int, "medium": int, "low": int,
          },
          "risk_score": int,   # weighted score: critical*10 + high*5 + medium*2 + low*1
        }
    """
    ref   = [l.rstrip("\n") for l in reference_lines]
    cur   = [l.rstrip("\n") for l in current_lines]

    matcher = difflib.SequenceMatcher(None, ref, cur, autojunk=False)
    changes: list[dict] = []
    ref_no = 0
    cur_no = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            # Emit a small context window (3 lines) around changes for readability
            for k in range(i1, i2):
                changes.append({
                    "ref_line_no": k + 1,
                    "cur_line_no": j1 + (k - i1) + 1,
                    "action":      "context",
                    "content":     ref[k],
                    "risk_level":  "info",
                    "risk_reason": "",
                })
        elif tag in ("replace", "delete"):
            for k in range(i1, i2):
                risk_level, risk_reason = _classify_change(ref[k], "remove")
                changes.append({
                    "ref_line_no": k + 1,
                    "cur_line_no": None,
                    "action":      "remove",
                    "content":     ref[k],
                    "risk_level":  risk_level,
                    "risk_reason": risk_reason,
                })
        if tag in ("replace", "insert"):
            for k in range(j1, j2):
                risk_level, risk_reason = _classify_change(cur[k], "add")
                changes.append({
                    "ref_line_no": None,
                    "cur_line_no": k + 1,
                    "action":      "add",
                    "content":     cur[k],
                    "risk_level":  risk_level,
                    "risk_reason": risk_reason,
                })

    # Trim context to 3-line windows around actual changes — collapse large equal blocks
    changes = _trim_context(changes, context_lines=3)

    added   = sum(1 for c in changes if c["action"] == "add")
    removed = sum(1 for c in changes if c["action"] == "remove")
    summary = {
        "total_changes": added + removed,
        "lines_added":   added,
        "lines_removed": removed,
        "critical":      sum(1 for c in changes if c["action"] != "context" and c["risk_level"] == "critical"),
        "high":          sum(1 for c in changes if c["action"] != "context" and c["risk_level"] == "high"),
        "medium":        sum(1 for c in changes if c["action"] != "context" and c["risk_level"] == "medium"),
        "low":           sum(1 for c in changes if c["action"] != "context" and c["risk_level"] == "low"),
    }
    risk_score = (
        summary["critical"] * 10
        + summary["high"]   *  5
        + summary["medium"] *  2
        + summary["low"]    *  1
    )

    return {"changes": changes, "summary": summary, "risk_score": risk_score}


def _trim_context(changes: list[dict], context_lines: int = 3) -> list[dict]:
    """
    Keep only context lines within `context_lines` of an actual change.
    Replace large unchanged blocks with a single '...' separator entry.
    """
    n = len(changes)
    keep = [False] * n
    for i, c in enumerate(changes):
        if c["action"] != "context":
            for j in range(max(0, i - context_lines), min(n, i + context_lines + 1)):
                keep[j] = True

    result: list[dict] = []
    skipped = 0
    for i, c in enumerate(changes):
        if keep[i]:
            if skipped > 0:
                result.append({
                    "ref_line_no": None, "cur_line_no": None,
                    "action": "separator", "content": f"… {skipped} unchanged lines …",
                    "risk_level": "info", "risk_reason": "",
                })
                skipped = 0
            result.append(c)
        else:
            skipped += 1
    if skipped > 0:
        result.append({
            "ref_line_no": None, "cur_line_no": None,
            "action": "separator", "content": f"… {skipped} unchanged lines …",
            "risk_level": "info", "risk_reason": "",
        })
    return result


def _risk_color(level: str) -> str:
    return {"critical": "\033[91m", "high": "\033[93m",
            "medium": "\033[94m", "low": "\033[37m"}.get(level, "")

_RESET = "\033[0m"


def _print_diff_result(result: dict, min_risk: str = "info", use_color: bool = True) -> None:
    s = result["summary"]
    score = result["risk_score"]
    print(f"\n{'='*70}")
    print(f"Config Diff Risk Analysis")
    print(f"{'='*70}")
    print(f"  Added   : {s['lines_added']} lines")
    print(f"  Removed : {s['lines_removed']} lines")
    print(f"  Risk Score: {score}")
    print(f"  Critical: {s['critical']}  High: {s['high']}  Medium: {s['medium']}  Low: {s['low']}")
    print(f"{'='*70}\n")

    min_rank = RISK_ORDER.get(min_risk, 0)
    threshold_changes = [
        c for c in result["changes"]
        if c["action"] == "separator"
        or c["action"] == "context"
        or RISK_ORDER.get(c["risk_level"], 0) >= min_rank
    ]

    for c in threshold_changes:
        action = c["action"]
        content = c["content"]
        risk_level = c["risk_level"]
        risk_reason = c["risk_reason"]

        if action == "separator":
            print(f"  \033[90m{content}\033[0m")
            continue
        if action == "context":
            print(f"    {content}")
            continue

        prefix = "+" if action == "add" else "-"
        color  = _risk_color(risk_level) if use_color else ""
        reset  = _RESET if use_color else ""
        badge  = f"[{RISK_LABELS.get(risk_level, '')}]" if risk_reason else ""
        reason = f"  ← {risk_reason}" if risk_reason else ""
        print(f"  {color}{prefix} {content}{reset}{reason}  {badge}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cisco Config Diff Risk Analyzer")
    parser.add_argument("--reference", metavar="FILE", required=False,
                        help="Reference config file (startup / baseline)")
    parser.add_argument("--current",   metavar="FILE", required=False,
                        help="Current config file (running / proposed)")
    parser.add_argument("--min-risk",  default="info",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Minimum risk level to display (default: info = show all)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colour")
    args = parser.parse_args()

    if not args.reference or not args.current:
        parser.error("--reference and --current are both required")

    try:
        ref_lines = Path(args.reference).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        cur_lines = Path(args.current).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    result = analyze_diff(ref_lines, cur_lines)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    _print_diff_result(result, min_risk=args.min_risk, use_color=not args.no_color)


if __name__ == "__main__":
    main()
