# probes/fingerprint.py
#
# Fingerprinting analysis — processes raw probe results into fingerprint signals.
# Does NOT send packets. Takes collected data and produces inferences.
#
# This is the layer that turns raw TTL=64 into "likely Linux" and
# IPID diffs=[1,1,1,2,1] into "sequential IPID — idle scan feasible".

import math
import statistics


# ---------------------------------------------------------------------------
# OS Fingerprinting
# Uses multiple signals for a more accurate guess than TTL alone.
# Signals: TTL, initial window size, TCP options order.
#
# This mimics what Nmap's OS detection does — cross-reference multiple
# behavioral signals against known OS profiles.
# ---------------------------------------------------------------------------

# Known OS signatures based on SYN-ACK characteristics
OS_SIGNATURES = {
    "Linux (kernel 3.x-5.x)": {
        "ttl_range": (60, 65),
        "window_sizes": [5840, 14600, 29200, 65495, 65535],
        "options_order": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
    },
    "Linux (kernel 6.x)": {
        "ttl_range": (60, 65),
        "window_sizes": [32768, 65535],
        "options_order": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
    },
    "Windows 10/11": {
        "ttl_range": (124, 129),
        "window_sizes": [8192, 65535, 64240],
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
    },
    "Windows Server 2016/2019": {
        "ttl_range": (124, 129),
        "window_sizes": [8192, 65535],
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
    },
    "FreeBSD / macOS": {
        "ttl_range": (62, 65),
        "window_sizes": [65535],
        "options_order": ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"],
    },
    "Network Device (Cisco IOS)": {
        "ttl_range": (250, 256),
        "window_sizes": [4128],
        "options_order": [],
    },
}


def _ttl_os_guess(ttl):
    """Initial TTL based OS guess — coarse but fast."""
    if ttl is None:
        return "Unknown"
    if ttl <= 65:
        return "Linux/Unix (TTL~64)"
    if ttl <= 130:
        return "Windows (TTL~128)"
    if ttl > 200:
        return "Network device / Cisco (TTL~255)"
    return "Unknown"


def fingerprint_os(ttl, window_size=None, tcp_options=None):
    """
    Cross-references TTL, window size, and TCP options order to produce
    an OS fingerprint with a confidence level.

    Returns dict with best_match, confidence, all_signals, and os_family.
    """
    signals = {
        "ttl":          ttl,
        "window_size":  window_size,
        "tcp_options":  tcp_options,
        "ttl_guess":    _ttl_os_guess(ttl),
    }

    if ttl is None:
        return {
            "best_match":  "Unknown",
            "confidence":  "none",
            "os_family":   "unknown",
            "signals":     signals,
            "fingerprint_summary": "No TTL available — cannot fingerprint",
        }

    scores = {}
    options_names = [opt[0] for opt in tcp_options] if tcp_options else []

    for os_name, profile in OS_SIGNATURES.items():
        score = 0

        # TTL match
        lo, hi = profile["ttl_range"]
        if lo <= ttl <= hi:
            score += 3

        # Window size match
        if window_size and window_size in profile["window_sizes"]:
            score += 3

        # TCP options order match
        if options_names and profile["options_order"]:
            matched = sum(1 for o in profile["options_order"] if o in options_names)
            score += matched

        scores[os_name] = score

    if not scores or max(scores.values()) == 0:
        best = _ttl_os_guess(ttl)
        confidence = "low"
        os_family = "linux" if ttl <= 65 else ("windows" if ttl <= 130 else "network_device")
    else:
        best = max(scores, key=scores.get)
        top_score = scores[best]
        confidence = "high" if top_score >= 6 else ("medium" if top_score >= 3 else "low")
        os_family = (
            "linux"          if "Linux"   in best else
            "windows"        if "Windows" in best else
            "bsd_macos"      if "FreeBSD" in best or "macOS" in best else
            "network_device" if "Cisco"   in best else
            "unknown"
        )

    summary = (
        f"Best match: {best} (confidence: {confidence}) | "
        f"TTL={ttl}, WinSize={window_size}, "
        f"Options=[{', '.join(options_names[:5])}]"
    )

    return {
        "best_match":           best,
        "confidence":           confidence,
        "os_family":            os_family,
        "all_scores":           scores,
        "signals":              signals,
        "fingerprint_summary":  summary,
    }


# ---------------------------------------------------------------------------
# IPID Entropy Analysis
# Analyzes the sequence of IP ID values from repeated probes.
#
# IP ID field is 16 bits. OSes handle it differently:
#   Linux (modern)   : per-connection random IPID — not useful for idle scan
#   Linux (old)      : global counter — sequential, idle scan feasible
#   Windows          : random per-destination — partially predictable
#   BSD / macOS      : randomized — not useful for idle scan
#   Network devices  : often sequential — idle scan feasible
#
# Sequential IPID = the host can be used as an idle scan zombie.
# This means an attacker can perform anonymous port scans using this host.
# ---------------------------------------------------------------------------
def analyze_ipid_entropy(ipid_values):
    result = {
        "ipid_values":       ipid_values,
        "diffs":             [],
        "mean_diff":         None,
        "diff_variance":     None,
        "pattern":           "unknown",
        "idle_scan_feasible": False,
        "summary":           "",
    }

    if len(ipid_values) < 3:
        result["summary"] = "Insufficient IPID samples for analysis"
        return result

    diffs = []
    for i in range(len(ipid_values) - 1):
        d = ipid_values[i+1] - ipid_values[i]
        # Handle 16-bit wraparound
        if d < 0:
            d += 65536
        diffs.append(d)

    result["diffs"] = diffs
    result["mean_diff"] = round(statistics.mean(diffs), 2)

    try:
        result["diff_variance"] = round(statistics.variance(diffs), 2)
    except Exception:
        result["diff_variance"] = 0

    mean_d = result["mean_diff"]
    var_d  = result["diff_variance"]

    # Classification logic:
    # Sequential: mean ~1-5, low variance
    # Incremental: mean ~5-100, moderate variance (system activity based)
    # Random: high variance relative to mean, or mean > 1000

    if mean_d <= 5 and var_d <= 10:
        result["pattern"]             = "sequential"
        result["idle_scan_feasible"]  = True
        result["summary"] = (
            f"IPID is sequential (mean_diff={mean_d}, variance={var_d}). "
            "Host usable as idle scan zombie. Anonymous port scanning feasible."
        )
    elif mean_d <= 150 and var_d <= 5000:
        result["pattern"]             = "incremental_low_entropy"
        result["idle_scan_feasible"]  = True
        result["summary"] = (
            f"IPID increments predictably (mean_diff={mean_d}, variance={var_d}). "
            "Pattern suggests system-load-based counter. Idle scan partially feasible."
        )
    elif mean_d > 1000 or var_d > 50000:
        result["pattern"]             = "randomized"
        result["idle_scan_feasible"]  = False
        result["summary"] = (
            f"IPID appears randomized (mean_diff={mean_d}, variance={var_d}). "
            "Idle scan not feasible — good configuration."
        )
    else:
        result["pattern"]             = "mixed"
        result["idle_scan_feasible"]  = False
        result["summary"] = (
            f"IPID pattern unclear (mean_diff={mean_d}, variance={var_d}). "
            "Likely per-connection or partially randomized."
        )

    return result


# ---------------------------------------------------------------------------
# TCP Options Fingerprint
# Parses TCP options from a SYN-ACK and maps them to known OS profiles.
# The ORDER and PRESENCE of options is the fingerprinting signal.
#
# Options of interest:
#   MSS (2)        — Maximum Segment Size; value differs per OS
#   NOP (1)        — padding; position matters
#   WScale (3)     — Window Scaling; value differs per OS  
#   SAckOK (4)     — SACK permitted; most modern OSes enable this
#   Timestamp (8)  — TCP timestamps; value leaks uptime
# ---------------------------------------------------------------------------
def analyze_tcp_options(options_list):
    result = {
        "options_raw":   options_list,
        "options_names": [],
        "mss_value":     None,
        "wscale_value":  None,
        "sack_enabled":  False,
        "timestamps_enabled": False,
        "fingerprint_string": "",
        "summary": "",
    }

    if not options_list:
        result["summary"] = "No TCP options present — unusual; may indicate stripped options"
        return result

    names = []
    for opt in options_list:
        kind = opt[0]
        data = opt[1] if len(opt) > 1 else None

        if   kind == "MSS":       result["mss_value"]  = data; names.append("MSS")
        elif kind == "NOP":       names.append("NOP")
        elif kind == "WScale":    result["wscale_value"] = data; names.append("WScale")
        elif kind == "SAckOK":    result["sack_enabled"] = True; names.append("SAckOK")
        elif kind == "Timestamp": result["timestamps_enabled"] = True; names.append("Timestamp")
        elif kind == "EOL":       names.append("EOL")
        else:                     names.append(str(kind))

    result["options_names"]      = names
    result["fingerprint_string"] = "-".join(names)

    summary_parts = [f"Options order: {result['fingerprint_string']}"]
    if result["mss_value"]:
        summary_parts.append(f"MSS={result['mss_value']}")
    if result["wscale_value"] is not None:
        summary_parts.append(f"WScale={result['wscale_value']}")
    if result["timestamps_enabled"]:
        summary_parts.append("Timestamps ENABLED (uptime leakage risk)")
    if result["sack_enabled"]:
        summary_parts.append("SACK enabled")

    result["summary"] = " | ".join(summary_parts)
    return result