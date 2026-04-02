# analysis/scorer.py
#
# Weighted offensive risk scoring model.
# This is the novel contribution of the research —
# a unified misconfiguration risk score based purely on behavioral signals.
#
# Score = sum of triggered weights, normalized to 0-10.
# Higher score = more attack vectors enabled = higher offensive risk.
#
# Each weight is calibrated by:
#   1. How directly the misconfiguration enables an offensive technique
#   2. How much attacker capability it provides
#   3. Whether it's a prerequisite for more advanced attacks

from config import SCORE_WEIGHTS, HIGH_RISK_PORTS, LOW_RISK_PORTS, RAW_SCORE_CAP


def calculate_score(analysis, ipid_analysis, isn_analysis, syn_cookie,
                    icmp_echo, icmp_timestamp, icmp_rate_limit,
                    null_results, fin_results, xmas_results,
                    ack_results, os_fingerprint, tcp_options_analysis):
    """
    Returns a score dict with:
      - normalized_score: 0.0 to 10.0
      - risk_level: Low / Medium / High / Critical
      - triggered: list of (factor, weight, reason) tuples
      - raw_score: sum before normalization
    """

    triggered = []
    raw = 0

    def add(factor, reason):
        w = SCORE_WEIGHTS.get(factor, 0)
        triggered.append({
            "factor":  factor,
            "weight":  w,
            "reason":  reason,
        })
        return w

    # --- ISN entropy (highest offensive impact) ---
    if isn_analysis and isn_analysis.get("verdict") == "low_entropy_predictable":
        raw += add("isn_low_entropy",
                   f"ISN entropy score {isn_analysis.get('entropy_score')} — "
                   "sequence prediction and session hijacking feasible")

    # --- SYN cookie absent ---
    if syn_cookie and ("absent" in syn_cookie.get("verdict", "") or
                       "limited" in syn_cookie.get("verdict", "")):
        raw += add("no_syn_cookies",
                   f"SYN cookie protection absent — "
                   f"only {syn_cookie.get('responses_received', 0)} responses to rapid SYNs")

    # --- IPID predictability ---
    if ipid_analysis and ipid_analysis.get("idle_scan_feasible"):
        raw += add("ipid_predictable",
                   f"IPID pattern: {ipid_analysis.get('pattern')} — "
                   "idle scan (anonymous scanning) enabled")

    # --- Malformed flag responses ---
    malformed_count = (
        sum(1 for r in null_results  if r["status"] == "responded_rst") +
        sum(1 for r in fin_results   if r["status"] == "responded_rst") +
        sum(1 for r in xmas_results  if r["status"] == "responded_rst")
    )
    if malformed_count > 0:
        raw += add("malformed_flags_responded",
                   f"{malformed_count} malformed TCP probes (NULL/FIN/XMAS) returned RST — "
                   "stateful packet filter absent; filter evasion applicable")

    # --- High risk open ports (per port) ---
    for port in analysis.get("high_risk_open", []):
        raw += add("open_high_risk_port",
                   f"Port {port} open — high-value service directly accessible")

    # --- ICMP timestamp ---
    if icmp_timestamp and icmp_timestamp.get("status") == "timestamp_reply_received":
        raw += add("icmp_timestamp_enabled",
                   f"ICMP timestamp reply received — uptime/clock leakage confirmed")

    # --- ICMP no rate limit ---
    if icmp_rate_limit and icmp_rate_limit.get("verdict") == "no_rate_limit_detected":
        raw += add("icmp_no_rate_limit",
                   f"No ICMP rate limiting — {icmp_rate_limit.get('response_rate', 0)*100:.0f}% "
                   "response rate to burst")

    # --- OS fingerprinted ---
    if os_fingerprint and os_fingerprint.get("confidence") in ("high", "medium"):
        raw += add("os_fingerprinted",
                   f"OS confirmed as {os_fingerprint.get('best_match')} "
                   f"({os_fingerprint.get('confidence')} confidence)")

    # --- ACK unfiltered ---
    unfiltered_ack = sum(1 for r in ack_results if r["status"] == "unfiltered")
    if unfiltered_ack > 0:
        raw += add("ack_unfiltered",
                   f"{unfiltered_ack} port(s) returned RST to unsolicited ACK — "
                   "stateful filtering gap present")

    # --- ICMP echo enabled ---
    if icmp_echo and icmp_echo.get("status") == "reachable":
        raw += add("icmp_echo_enabled",
                   "ICMP echo replies active — host trivially discoverable")

    # --- TTL exposes OS ---
    if os_fingerprint and os_fingerprint.get("signals", {}).get("ttl") is not None:
        ttl = os_fingerprint["signals"]["ttl"]
        if ttl is not None:
            raw += add("ttl_exposes_os",
                       f"TTL={ttl} confirms OS family — passive fingerprinting enabled")

    # --- Low risk open ports (per port) ---
    low_risk_open = [p for p in analysis.get("open_ports", [])
                     if p in LOW_RISK_PORTS]
    for port in low_risk_open:
        raw += add("open_low_risk_port",
                   f"Port {port} open — service accessible")

    # --- TCP options fingerprint ---
    if tcp_options_analysis and tcp_options_analysis.get("fingerprint_string"):
        raw += add("tcp_options_fingerprint",
                   f"TCP options fingerprint: {tcp_options_analysis.get('fingerprint_string')} — "
                   "partial OS identity leakage via options order")

    # --- Normalize to 0-10 ---
    normalized = round(min(raw / RAW_SCORE_CAP, 1.0) * 10, 1)

    # --- Risk level bands ---
    if normalized <= 2.0:
        risk_level = "Low"
        risk_color = "GREEN"
    elif normalized <= 4.5:
        risk_level = "Medium"
        risk_color = "YELLOW"
    elif normalized <= 7.0:
        risk_level = "High"
        risk_color = "ORANGE"
    else:
        risk_level = "Critical"
        risk_color = "RED"

    return {
        "normalized_score": normalized,
        "raw_score":        raw,
        "score_cap":        RAW_SCORE_CAP,
        "risk_level":       risk_level,
        "risk_color":       risk_color,
        "triggered":        triggered,
        "total_factors":    len(triggered),
        "explanation": (
            "Score is computed by summing offensive-impact weights for each confirmed "
            "misconfiguration, then normalizing to a 0-10 scale. "
            "Each weight reflects the degree of attacker capability enabled."
        ),
    }


def generate_mitigations(score_data, os_fingerprint=None):
    """
    Generates targeted mitigation recommendations based on triggered factors.
    Each mitigation maps directly to the offensive capability it closes.
    """
    mitigations = []

    # Priority map: factor → mitigation
    MITIGATION_MAP = {
        "isn_low_entropy": {
            "issue":    "Low ISN entropy — session prediction feasible",
            "fix":      "Upgrade to a modern kernel with cryptographic ISN generation (RFC 6528). "
                        "Linux kernels >= 4.x use PRNG-based ISN. "
                        "Ensure no custom TCP stack or stripped-down firmware is in use.",
            "severity": "Critical",
        },
        "no_syn_cookies": {
            "issue":    "SYN cookie protection absent or limited",
            "fix":      "Enable SYN cookies: `sysctl net.ipv4.tcp_syncookies=1` on Linux. "
                        "Increase SYN backlog: `sysctl net.ipv4.tcp_max_syn_backlog=4096`. "
                        "Deploy SYN flood rate limiting at the firewall/router.",
            "severity": "Critical",
        },
        "ipid_predictable": {
            "issue":    "Predictable IPID — idle scan zombie feasibility",
            "fix":      "Modern Linux kernels (>= 3.x) use per-connection random IPID by default. "
                        "Ensure the system is not running legacy kernel. "
                        "Network-level mitigation: egress filtering via BCP38.",
            "severity": "High",
        },
        "malformed_flags_responded": {
            "issue":    "Malformed TCP packets (NULL/FIN/XMAS) not dropped",
            "fix":      "Implement stateful packet inspection via iptables/nftables/pf. "
                        "Rule: drop packets with illegal flag combinations. "
                        "Linux: `iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP` (NULL). "
                        "For XMAS: `iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP`.",
            "severity": "High",
        },
        "open_high_risk_port": {
            "issue":    "High-risk service ports exposed",
            "fix":      "Disable unused services. Move SSH to non-standard port. "
                        "Disable Telnet entirely — replace with SSH. "
                        "Restrict SMB/NetBIOS to internal network only via firewall. "
                        "Use allowlist-based firewall rules.",
            "severity": "High",
        },
        "icmp_timestamp_enabled": {
            "issue":    "ICMP timestamp replies enabled — uptime leakage",
            "fix":      "Linux: `iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP`. "
                        "Alternatively: `sysctl net.ipv4.icmp_echo_ignore_all=1` blocks all ICMP. "
                        "Block ICMP Type 13/14 at perimeter firewall.",
            "severity": "Medium",
        },
        "icmp_no_rate_limit": {
            "issue":    "No ICMP rate limiting — flood feasibility elevated",
            "fix":      "Linux: `sysctl net.ipv4.icmp_ratelimit=200` (200ms token bucket). "
                        "Set `net.ipv4.icmp_ratemask` to include echo replies. "
                        "Apply rate limiting at perimeter: `iptables -A INPUT -p icmp -m limit "
                        "--limit 10/second -j ACCEPT`.",
            "severity": "Medium",
        },
        "os_fingerprinted": {
            "issue":    "OS identity confirmed through behavioral fingerprinting",
            "fix":      "Deploy packet normalization at perimeter (pf scrub, iptables NFQUEUE). "
                        "Randomize or clamp TTL values at the firewall. "
                        "Strip or randomize TCP options at the gateway. "
                        "Consider OS fingerprint scrubbing tools (OpenBSD pf `scrub` directive).",
            "severity": "Medium",
        },
        "ack_unfiltered": {
            "issue":    "Unsolicited ACK packets reaching the host — stateful filtering gap",
            "fix":      "Configure stateful firewall (iptables conntrack): "
                        "`iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT` "
                        "`iptables -A INPUT -m state --state INVALID -j DROP`. "
                        "Drop packets that don't belong to an existing connection.",
            "severity": "Medium",
        },
        "icmp_echo_enabled": {
            "issue":    "ICMP echo replies enabled — host discoverable",
            "fix":      "Restrict ICMP echo on external interfaces: "
                        "`sysctl net.ipv4.icmp_echo_ignore_all=1` or firewall rule. "
                        "Allow ICMP only from trusted management networks.",
            "severity": "Low",
        },
        "ttl_exposes_os": {
            "issue":    "TTL value reveals OS family",
            "fix":      "Normalize outgoing TTL at the firewall/gateway. "
                        "pf: `scrub out all random-id min-ttl 64`. "
                        "iptables: use NFQUEUE or MANGLE table to normalize TTL.",
            "severity": "Low",
        },
        "tcp_options_fingerprint": {
            "issue":    "TCP options order leaks OS identity",
            "fix":      "Use traffic normalization at perimeter to strip or reorder TCP options. "
                        "OpenBSD pf `scrub` rewrites TCP options. "
                        "Application-layer proxies (nginx, HAProxy) terminate TCP and re-originate, "
                        "masking underlying OS options.",
            "severity": "Low",
        },
    }

    seen_factors = set()
    for item in score_data.get("triggered", []):
        factor = item["factor"]
        if factor in MITIGATION_MAP and factor not in seen_factors:
            m = MITIGATION_MAP[factor].copy()
            m["factor"] = factor
            mitigations.append(m)
            seen_factors.add(factor)

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    mitigations.sort(key=lambda x: sev_order.get(x["severity"], 4))

    if not mitigations:
        mitigations.append({
            "factor":   "none",
            "issue":    "No significant misconfigurations detected",
            "fix":      "Maintain current configuration. Apply regular updates. "
                        "Re-run analysis periodically as configurations change.",
            "severity": "Low",
        })

    return mitigations