# reporter/generator.py
#
# Generates JSON and plain-text reports from analysis results.
# JSON is machine-readable — useful for future ML/dataset work.
# TXT is human-readable — structured like a penetration test report.

import json
import os
from datetime import datetime

from config import PROJECT_TITLE


def _timestamp():
    return datetime.now().isoformat()


def _safe_filename(target):
    return target.replace(".", "_").replace(":", "_").replace("/", "_")


def generate(
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
    analysis,
    score_data,
    mitigations,
    investigator="",
    output_dir="reports",
):
    os.makedirs(output_dir, exist_ok=True)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{_safe_filename(target)}_{ts}"
    json_path = os.path.join(output_dir, base_name + ".json")
    txt_path  = os.path.join(output_dir, base_name + ".txt")

    # -----------------------------------------------------------------------
    # JSON Report — full raw data, all probe results
    # -----------------------------------------------------------------------
    payload = {
        "meta": {
            "project":      PROJECT_TITLE,
            "generated_at": _timestamp(),
            "target":       target,
            "investigator": investigator,
        },
        "probes": {
            "tcp_syn":           syn_results,
            "tcp_ack":           ack_results,
            "tcp_null":          null_results,
            "tcp_fin":           fin_results,
            "tcp_xmas":          xmas_results,
            "icmp_echo":         icmp_echo,
            "icmp_timestamp":    icmp_timestamp,
            "icmp_rate_limit":   icmp_rate_limit,
            "repeated_icmp":     repeated_icmp,
            "isn_analysis":      isn_analysis,
            "syn_cookie":        syn_cookie,
        },
        "fingerprinting": {
            "ipid_analysis":      ipid_analysis,
            "os_fingerprint":     os_fingerprint,
            "tcp_options":        tcp_options_analysis,
        },
        "analysis":     analysis,
        "score":        score_data,
        "mitigations":  mitigations,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, default=str)

    # -----------------------------------------------------------------------
    # TXT Report — human-readable structured report
    # -----------------------------------------------------------------------
    lines = []

    def h1(text):
        lines.append("")
        lines.append("=" * 72)
        lines.append(f"  {text}")
        lines.append("=" * 72)

    def h2(text):
        lines.append("")
        lines.append(f"  [ {text} ]")
        lines.append("  " + "-" * 50)

    def row(label, value):
        lines.append(f"  {label:<30} {value}")

    def bullet(text):
        lines.append(f"    • {text}")

    h1(PROJECT_TITLE)
    row("Generated At :", _timestamp())
    row("Target       :", target)
    if investigator:
        row("Investigator :", investigator)
    row("Risk Level   :", f"{score_data['risk_level']}  "
                          f"(Score: {score_data['normalized_score']}/10)")

    # -----------------------------------------------------------------------
    h2("1. TCP SYN PROBE RESULTS")
    lines.append(f"  {'Port':<8} {'Service':<12} {'Status':<22} {'TTL':<6} {'WinSize':<10} {'Summary'}")
    lines.append("  " + "-" * 70)
    for r in syn_results:
        lines.append(
            f"  {r['port']:<8} {r['service']:<12} {r['status']:<22} "
            f"{str(r.get('ttl','')):<6} {str(r.get('window_size','')):<10} "
            f"{r['response_summary']}"
        )

    # -----------------------------------------------------------------------
    h2("2. TCP ACK PROBE RESULTS (Firewall Detection)")
    for r in ack_results:
        bullet(f"Port {r['port']} ({r['service']}): {r['status']} — {r['response_summary']}")

    # -----------------------------------------------------------------------
    h2("3. MALFORMED TCP FLAG PROBES (Filter Evasion Assessment)")
    lines.append("  NULL Probes:")
    for r in null_results:
        bullet(f"Port {r['port']}: {r['status']} — {r['response_summary']}")
    lines.append("  FIN Probes:")
    for r in fin_results:
        bullet(f"Port {r['port']}: {r['status']} — {r['response_summary']}")
    lines.append("  XMAS Probes:")
    for r in xmas_results:
        bullet(f"Port {r['port']}: {r['status']} — {r['response_summary']}")

    # -----------------------------------------------------------------------
    h2("4. ICMP ANALYSIS")
    bullet(f"Echo probe:      {icmp_echo.get('response_summary', 'N/A')}")
    bullet(f"Timestamp probe: {icmp_timestamp.get('response_summary', 'N/A')}")
    bullet(f"Rate limit test: {icmp_rate_limit.get('response_summary', 'N/A')}")
    bullet(f"Repeated ICMP:   {repeated_icmp.get('response_summary', 'N/A')}")

    # -----------------------------------------------------------------------
    h2("5. FINGERPRINTING")
    if os_fingerprint:
        bullet(f"OS Fingerprint: {os_fingerprint.get('fingerprint_summary', 'N/A')}")
    if ipid_analysis:
        bullet(f"IPID Analysis:  {ipid_analysis.get('summary', 'N/A')}")
    if tcp_options_analysis:
        bullet(f"TCP Options:    {tcp_options_analysis.get('summary', 'N/A')}")

    # -----------------------------------------------------------------------
    h2("6. ISN ENTROPY ANALYSIS")
    if isn_analysis:
        bullet(f"Verdict:        {isn_analysis.get('verdict', 'N/A')}")
        bullet(f"Entropy Score:  {isn_analysis.get('entropy_score', 'N/A')} (0=predictable, 1=random)")
        bullet(f"ISN Values:     {isn_analysis.get('isn_values', [])}")
        bullet(f"ISN Diffs:      {isn_analysis.get('isn_diffs', [])}")
        bullet(isn_analysis.get('response_summary', ''))

    # -----------------------------------------------------------------------
    h2("7. SYN COOKIE DETECTION")
    if syn_cookie:
        bullet(f"Verdict:       {syn_cookie.get('verdict', 'N/A')}")
        bullet(syn_cookie.get("response_summary", "N/A"))

    # -----------------------------------------------------------------------
    h2("8. FINDINGS")
    for f in analysis.get("findings", []):
        bullet(f)

    # -----------------------------------------------------------------------
    h2("9. ATTACK VECTOR MAP")
    vectors = analysis.get("attack_vectors", {})
    if vectors:
        for vid, vdata in vectors.items():
            lines.append(f"  ▶  {vdata['name']}")
            lines.append(f"       {vdata['attack']}")
    else:
        bullet("No active attack vectors confirmed")

    # -----------------------------------------------------------------------
    h2("10. RISK NARRATIVE")
    lines.append(f"  {analysis.get('risk_narrative', '')}")

    # -----------------------------------------------------------------------
    h2("11. SCORING BREAKDOWN")
    row("Final Score  :", f"{score_data['normalized_score']} / 10")
    row("Risk Level   :", score_data["risk_level"])
    row("Raw Score    :", f"{score_data['raw_score']} / {score_data['score_cap']}")
    lines.append("")
    lines.append("  Triggered Factors:")
    for item in score_data.get("triggered", []):
        lines.append(f"    [{item['weight']:>3}pt]  {item['reason']}")
    lines.append("")
    lines.append(f"  Scoring Method: {score_data['explanation']}")

    # -----------------------------------------------------------------------
    h2("12. MITIGATION RECOMMENDATIONS")
    for m in mitigations:
        lines.append(f"  [{m['severity']}] {m['issue']}")
        lines.append(f"  Fix: {m['fix']}")
        lines.append("")

    # -----------------------------------------------------------------------
    h1("END OF REPORT")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return json_path, txt_path