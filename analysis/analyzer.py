# analysis/analyzer.py
#
# Takes all raw probe results and produces a structured analysis.
# Maps each finding directly to the offensive capability it enables.
#
# This is the "so what" layer — raw data becomes actionable intelligence.

from config import HIGH_RISK_PORTS, LOW_RISK_PORTS


# Attack vector definitions — each maps to specific probe findings.
# This is what makes the research paper's offensive angle concrete.

ATTACK_VECTORS = {
    "host_discovery": {
        "name":        "Host Discovery",
        "description": "Confirming the host is alive and reachable",
        "attack":      "Reconnaissance phase — attacker confirms target before deeper probing",
    },
    "os_fingerprinting": {
        "name":        "OS Fingerprinting",
        "description": "Identifying target operating system from stack behavior",
        "attack":      "Attacker selects OS-specific exploits and attack tooling",
    },
    "port_enumeration": {
        "name":        "Port/Service Enumeration",
        "description": "Mapping open services on the target",
        "attack":      "Attacker identifies attack surface — each open port is a potential entry",
    },
    "idle_scan": {
        "name":        "Idle Scan (Anonymous Scanning)",
        "description": "Using predictable IPID to port scan without revealing true IP",
        "attack":      "Attacker performs anonymous port scans, evading detection and attribution",
    },
    "session_prediction": {
        "name":        "TCP Session Prediction",
        "description": "Predicting sequence numbers to inject into TCP streams",
        "attack":      "Session hijacking, data injection, or blind spoofing attacks",
    },
    "syn_flood": {
        "name":        "SYN Flood / DoS Feasibility",
        "description": "Assessing susceptibility to SYN queue exhaustion",
        "attack":      "Denial of service — overwhelm connection backlog, block legitimate users",
    },
    "icmp_flood": {
        "name":        "ICMP Flood Feasibility",
        "description": "Assessing ICMP flood and amplification potential",
        "attack":      "Bandwidth exhaustion or use as amplification reflector",
    },
    "filter_evasion": {
        "name":        "Firewall / Filter Evasion",
        "description": "Bypassing packet filters using malformed TCP flags",
        "attack":      "Attacker probes behind firewall using NULL/XMAS/FIN scans",
    },
    "uptime_leakage": {
        "name":        "Uptime and Identity Leakage",
        "description": "Extracting system clock and uptime from ICMP timestamps or TCP options",
        "attack":      "Identifies recently rebooted systems, correlates identity across NAT",
    },
}


def analyze(
    target,
    syn_results,
    ack_results,
    null_results,
    fin_results,
    xmas_results,
    icmp_echo,
    icmp_timestamp,
    icmp_rate_limit,
    repeated_icmp,
    isn_analysis,
    syn_cookie,
    ipid_analysis,
    os_fingerprint,
    tcp_options_analysis,
):
    """
    Aggregates all probe results into a structured analysis.
    Returns: findings list, attack_vector_map, and a concise risk narrative.
    """

    findings          = []
    attack_vector_map = {}
    active_vectors    = []

    # --- Host Discovery ---
    if icmp_echo.get("status") == "reachable":
        findings.append("ICMP echo replies enabled — host trivially discoverable")
        active_vectors.append("host_discovery")

    # --- Port State Analysis ---
    open_ports     = [r["port"] for r in syn_results if r["status"] == "open"]
    closed_ports   = [r["port"] for r in syn_results if r["status"] == "closed"]
    filtered_ports = [r["port"] for r in syn_results if r["status"] == "filtered"]

    if open_ports:
        port_list = [f"{p} ({_svc(p)})" for p in open_ports]
        findings.append(f"Open ports: {port_list}")
        active_vectors.append("port_enumeration")

    high_risk_open = [p for p in open_ports if p in HIGH_RISK_PORTS]
    if high_risk_open:
        findings.append(
            f"High-risk ports open: {[f'{p} ({_svc(p)})' for p in high_risk_open]} — "
            "SSH/Telnet/SMB/FTP directly accessible"
        )

    # --- OS Fingerprinting ---
    if os_fingerprint and os_fingerprint.get("confidence") in ("high", "medium"):
        findings.append(f"OS fingerprinted: {os_fingerprint['best_match']} "
                        f"(confidence: {os_fingerprint['confidence']})")
        active_vectors.append("os_fingerprinting")

    # --- IPID / Idle Scan ---
    if ipid_analysis and ipid_analysis.get("idle_scan_feasible"):
        findings.append(
            f"IPID pattern: {ipid_analysis['pattern']} — idle scan feasible. "
            "Host usable as zombie for anonymous port scanning."
        )
        active_vectors.append("idle_scan")

    # --- ISN Entropy ---
    if isn_analysis and isn_analysis.get("verdict") == "low_entropy_predictable":
        findings.append(
            f"Low ISN entropy — sequence prediction feasible. "
            f"Score: {isn_analysis.get('entropy_score')}"
        )
        active_vectors.append("session_prediction")

    # --- SYN Cookie / DoS ---
    if syn_cookie:
        v = syn_cookie.get("verdict", "")
        if "absent" in v or "limited" in v:
            findings.append("SYN cookie protection absent or limited — SYN flood DoS feasibility elevated")
            active_vectors.append("syn_flood")
        elif "active" in v:
            findings.append("SYN cookie protection likely active — SYN flood resistance present")

    # --- ICMP Flood ---
    if icmp_rate_limit and icmp_rate_limit.get("verdict") == "no_rate_limit_detected":
        findings.append(
            f"No ICMP rate limiting — responded to {icmp_rate_limit['responses_received']}/"
            f"{icmp_rate_limit['probes_sent']} rapid probes. ICMP flood feasibility elevated."
        )
        active_vectors.append("icmp_flood")

    # --- Malformed Flag Behavior (Filter Evasion) ---
    malformed_responses = []
    for r in null_results:
        if r["status"] == "responded_rst":
            malformed_responses.append(f"NULL/{r['port']}")
    for r in fin_results:
        if r["status"] == "responded_rst":
            malformed_responses.append(f"FIN/{r['port']}")
    for r in xmas_results:
        if r["status"] == "responded_rst":
            malformed_responses.append(f"XMAS/{r['port']}")

    if malformed_responses:
        findings.append(
            f"Malformed TCP probes received responses: {malformed_responses}. "
            "Stateful packet filtering absent — filter evasion techniques applicable."
        )
        active_vectors.append("filter_evasion")

    # --- ACK Filtering ---
    unfiltered_ack = [r["port"] for r in ack_results if r["status"] == "unfiltered"]
    if unfiltered_ack:
        findings.append(
            f"Unsolicited ACK probes returned RST on ports {unfiltered_ack} — "
            "limited stateful filtering; firewall gap present"
        )

    # --- Uptime / Clock Leakage ---
    if icmp_timestamp and icmp_timestamp.get("status") == "timestamp_reply_received":
        findings.append(
            f"ICMP timestamp replies enabled — clock skew: {icmp_timestamp.get('clock_skew_ms')}ms. "
            "Uptime estimation and identity correlation possible."
        )
        active_vectors.append("uptime_leakage")

    # TCP timestamp option leakage
    if tcp_options_analysis and tcp_options_analysis.get("timestamps_enabled"):
        findings.append("TCP timestamp option enabled in SYN-ACK — uptime leakage via TCP handshake")
        if "uptime_leakage" not in active_vectors:
            active_vectors.append("uptime_leakage")

    # --- Build attack vector map ---
    for v in active_vectors:
        if v in ATTACK_VECTORS:
            attack_vector_map[v] = ATTACK_VECTORS[v]

    # --- Risk Narrative ---
    if not findings:
        risk_narrative = (
            "No significant misconfiguration indicators detected across tested probes. "
            "The target appears to have baseline hardening in place."
        )
    else:
        n = len(active_vectors)
        risk_narrative = (
            f"{n} offensive attack vector(s) confirmed through behavioral probing: "
            f"{', '.join(ATTACK_VECTORS[v]['name'] for v in active_vectors)}. "
            "These misconfigurations are exploitable without any software vulnerabilities — "
            "purely through protocol behavior observation."
        )

    return {
        "target":            target,
        "findings":          findings,
        "attack_vectors":    attack_vector_map,
        "active_vector_ids": active_vectors,
        "open_ports":        open_ports,
        "closed_ports":      closed_ports,
        "filtered_ports":    filtered_ports,
        "high_risk_open":    high_risk_open,
        "risk_narrative":    risk_narrative,
    }


def _svc(port):
    from config import PORT_SERVICES
    return PORT_SERVICES.get(port, "Unknown")