# main.py
#
# Orchestrator — runs all probes in sequence, feeds results to analysis,
# scoring, and report generation.
#
# Probe execution order:
#   1. TCP SYN     — port state + TCP options for fingerprinting
#   2. TCP ACK     — stateful firewall detection
#   3. TCP NULL    — malformed flag handling
#   4. TCP FIN     — malformed flag handling
#   5. TCP XMAS    — malformed flag handling
#   6. ISN entropy — sequence number randomness (uses first open port found)
#   7. SYN cookie  — DoS protection assessment
#   8. ICMP echo   — host liveness
#   9. ICMP timestamp — uptime/clock leakage
#  10. ICMP rate limit — flood feasibility
#  11. Repeated ICMP — IPID collection for idle scan analysis
#
# Then: fingerprinting → analysis → scoring → mitigations → reports

import sys
from scapy.all import conf

from config import COMMON_PORTS, PORT_SERVICES, TARGET_TIMEOUT, ISN_SAMPLE_COUNT, SYN_COOKIE_TEST_COUNT, ICMP_RATE_TEST_COUNT

from probes.tcp_probes  import (syn_probe, ack_probe, null_probe,
                                fin_probe, xmas_probe,
                                isn_entropy_analysis, syn_cookie_detection)
from probes.icmp_probes import (echo_probe, timestamp_probe,
                                rate_limit_test, repeated_echo_analysis)
from probes.fingerprint import (fingerprint_os, analyze_ipid_entropy,
                                analyze_tcp_options)
from analysis.analyzer  import analyze
from analysis.scorer    import calculate_score, generate_mitigations
from reporter.generator import generate
from reporter.pdf_report import generate_pdf_report
conf.verb = 0


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _svc(port):
    return PORT_SERVICES.get(port, "Unknown")


def _section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _status(msg):
    print(f"  {msg}")


# -----------------------------------------------------------------------
# Probe suite runners
# -----------------------------------------------------------------------

def run_tcp_syn_probes(target, ports, timeout):
    results = []
    for port in ports:
        r = syn_probe(target, port, _svc(port), timeout)
        results.append(r)
        marker = "OPEN" if r["status"] == "open" else r["status"].upper()
        _status(f"[SYN] {port:>5} ({r['service']:<10}) → {marker}")
    return results


def run_tcp_ack_probes(target, ports, timeout):
    results = []
    for port in ports:
        r = ack_probe(target, port, _svc(port), timeout)
        results.append(r)
        _status(f"[ACK] {port:>5} ({r['service']:<10}) → {r['status']}")
    return results


def run_malformed_probes(target, ports, timeout):
    # Only test a subset — malformed probes on every port is noisy
    test_ports = ports[:6]
    null_results, fin_results, xmas_results = [], [], []

    for port in test_ports:
        null_results.append(null_probe(target, port, _svc(port), timeout))
        fin_results.append(fin_probe(target, port, _svc(port), timeout))
        xmas_results.append(xmas_probe(target, port, _svc(port), timeout))

    null_resp  = sum(1 for r in null_results  if r["status"] == "responded_rst")
    fin_resp   = sum(1 for r in fin_results   if r["status"] == "responded_rst")
    xmas_resp  = sum(1 for r in xmas_results  if r["status"] == "responded_rst")

    _status(f"[NULL] {null_resp}/{len(test_ports)} ports responded")
    _status(f"[FIN]  {fin_resp}/{len(test_ports)} ports responded")
    _status(f"[XMAS] {xmas_resp}/{len(test_ports)} ports responded")

    return null_results, fin_results, xmas_results



# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    print(f"\n{'#'*60}")
    print("  TCP/IP STACK MISCONFIGURATION ANALYZER")
    print("  For authorized testing only.")
    print(f"{'#'*60}\n")

    target = input("  Enter target IP address: ").strip()
    if not target:
        print("No target specified. Exiting.")
        sys.exit(1)

    investigator = input("  Enter investigator name (optional): ").strip()

    timeout = TARGET_TIMEOUT
    ports   = COMMON_PORTS

    # -------------------------------------------------------------------
    # Phase 1: TCP Probes
    # -------------------------------------------------------------------
    _section("Phase 1 — TCP SYN Probes")
    syn_results = run_tcp_syn_probes(target, ports, timeout)

    _section("Phase 2 — TCP ACK Probes (Firewall Detection)")
    ack_results = run_tcp_ack_probes(target, ports, timeout)

    _section("Phase 3 — Malformed TCP Flag Probes")
    null_results, fin_results, xmas_results = run_malformed_probes(target, ports, timeout)

    # -------------------------------------------------------------------
    # Phase 2: ISN and SYN Cookie (need an open port)
    # -------------------------------------------------------------------
    open_ports = [r["port"] for r in syn_results if r["status"] == "open"]
    target_port = open_ports[0] if open_ports else 80  # fallback to 80

    _section("Phase 4 — ISN Entropy Analysis")
    _status(f"Probing port {target_port} ({_svc(target_port)}) with {ISN_SAMPLE_COUNT} SYN probes...")
    isn_analysis = isn_entropy_analysis(target, target_port, _svc(target_port),
                                        count=ISN_SAMPLE_COUNT, timeout=timeout)
    _status(f"[ISN] {isn_analysis['verdict']} — {isn_analysis['response_summary']}")

    _section("Phase 5 — SYN Cookie Detection")
    _status(f"Sending {SYN_COOKIE_TEST_COUNT} rapid SYNs to port {target_port}...")
    syn_cookie = syn_cookie_detection(target, target_port, _svc(target_port),
                                      count=SYN_COOKIE_TEST_COUNT, timeout=timeout)
    _status(f"[SYN-COOKIE] {syn_cookie['verdict']}")
    _status(f"  {syn_cookie['response_summary']}")

    # -------------------------------------------------------------------
    # Phase 3: ICMP Probes
    # -------------------------------------------------------------------
    _section("Phase 6 — ICMP Echo Probe")
    icmp_echo = echo_probe(target, timeout)
    _status(f"[ICMP-ECHO] {icmp_echo['status']} — {icmp_echo['response_summary']}")

    _section("Phase 7 — ICMP Timestamp Probe")
    icmp_timestamp = timestamp_probe(target, timeout)
    _status(f"[ICMP-TS] {icmp_timestamp['status']}")
    _status(f"  {icmp_timestamp['response_summary']}")

    _section("Phase 8 — ICMP Rate Limit Test")
    _status(f"Sending {ICMP_RATE_TEST_COUNT} rapid ICMP probes...")
    icmp_rate_limit = rate_limit_test(target, count=ICMP_RATE_TEST_COUNT, timeout=timeout)
    _status(f"[ICMP-RATE] {icmp_rate_limit['verdict']} — {icmp_rate_limit['response_summary']}")

    _section("Phase 9 — Repeated ICMP (IPID Collection)")
    repeated_icmp = repeated_echo_analysis(target, count=5, timeout=timeout)
    _status(f"[REPEATED-ICMP] {repeated_icmp['response_summary']}")

    # -------------------------------------------------------------------
    # Phase 4: Fingerprinting (no new packets — processes collected data)
    # -------------------------------------------------------------------
    _section("Phase 10 — Fingerprinting Analysis")

    # Collect best TTL, window size, TCP options from SYN results
    best_syn = next((r for r in syn_results if r["status"] == "open"), None)
    ttl         = best_syn["ttl"]          if best_syn else repeated_icmp["ttl_values"][0] if repeated_icmp["ttl_values"] else None
    window_size = best_syn["window_size"]  if best_syn else None
    tcp_options = best_syn["tcp_options"]  if best_syn else None

    os_fingerprint      = fingerprint_os(ttl, window_size, tcp_options)
    ipid_values         = repeated_icmp.get("ipid_values", [])
    ipid_analysis       = analyze_ipid_entropy(ipid_values)
    tcp_options_analysis = analyze_tcp_options(tcp_options or [])

    _status(f"[OS] {os_fingerprint.get('fingerprint_summary', 'N/A')}")
    _status(f"[IPID] {ipid_analysis.get('summary', 'N/A')}")
    _status(f"[TCP-OPTS] {tcp_options_analysis.get('summary', 'N/A')}")

    # -------------------------------------------------------------------
    # Phase 5: Analysis, Scoring, Mitigations
    # -------------------------------------------------------------------
    _section("Phase 11 — Analysis & Attack Vector Mapping")
    analysis = analyze(
        target, syn_results, ack_results,
        null_results, fin_results, xmas_results,
        icmp_echo, icmp_timestamp, icmp_rate_limit,
        repeated_icmp, isn_analysis, syn_cookie,
        ipid_analysis, os_fingerprint, tcp_options_analysis,
    )
    for finding in analysis["findings"]:
        _status(f"  ► {finding}")

    _section("Phase 12 — Scoring")
    score_data = calculate_score(
        analysis, ipid_analysis, isn_analysis, syn_cookie,
        icmp_echo, icmp_timestamp, icmp_rate_limit,
        null_results, fin_results, xmas_results,
        ack_results, os_fingerprint, tcp_options_analysis,
    )
    print(f"\n  RISK SCORE : {score_data['normalized_score']} / 10")
    print(f"  RISK LEVEL : {score_data['risk_level']}")
    print(f"\n  Triggered factors ({score_data['total_factors']}):")
    for item in score_data["triggered"]:
        print(f"    [{item['weight']:>3}pt]  {item['reason']}")

    mitigations = generate_mitigations(score_data, os_fingerprint)

    _section("Phase 13 — Mitigation Summary")
    for m in mitigations:
        _status(f"  [{m['severity']}] {m['issue']}")

    _section("Phase 14 — Generating Reports")
    json_path, txt_path = generate(
        target,
        syn_results, ack_results,
        null_results, fin_results, xmas_results,
        icmp_echo, icmp_timestamp, icmp_rate_limit,
        repeated_icmp, isn_analysis, syn_cookie,
        ipid_analysis, os_fingerprint, tcp_options_analysis,
        analysis, score_data, mitigations,
        investigator=investigator,
    )
    _status(f"JSON → {json_path}")
    _status(f"TXT  → {txt_path}")

    # Build dictionaries for PDF Report
    tcp_results_dict = {
        "SYN Probes": syn_results,
        "ACK Probes": ack_results,
        "NULL Probes": null_results,
        "FIN Probes": fin_results,
        "XMAS Probes": xmas_results,
        "ISN Entropy": isn_analysis,
        "SYN Cookie Detection": syn_cookie,
    }

    icmp_results_dict = {
        "Echo Probe": icmp_echo,
        "Timestamp Probe": icmp_timestamp,
        "Rate Limit Test": icmp_rate_limit,
        "Repeated Echo Analysis": repeated_icmp,
    }

    fingerprint_results_dict = {
        "OS Fingerprint": os_fingerprint,
        "IPID Analysis": ipid_analysis,
        "TCP Options": tcp_options_analysis,
    }

    pdf_path = generate_pdf_report(
        target=target,
        tcp_results=tcp_results_dict,
        icmp_results=icmp_results_dict,
        fingerprint_results=fingerprint_results_dict,
        analysis=analysis,
        score_data=score_data,
        investigator=investigator,
    )
    _status(f"PDF  → {pdf_path}")

    print(f"\n{'#'*60}")
    print("  Analysis complete.")
    print(f"{'#'*60}\n")

if __name__ == "__main__":
    main()