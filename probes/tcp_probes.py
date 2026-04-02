# probes/tcp_probes.py
#
# All TCP-level probes for the TCP/IP Stack Misconfiguration Analyzer.
# Each probe returns a structured dictionary so the analyzer can process
# all probe outputs consistently.

import time
import statistics

from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.config import conf
from scapy.volatile import RandShort

conf.verb = 0


# ---------------------------------------------------------------------------
# Common Result Templates
# ---------------------------------------------------------------------------
def _base_result(probe_type, port, service):
    return {
        "probe_type": probe_type,
        "port": port,
        "service": service,
        "status": "unknown",
        "flags": None,
        "ttl": None,
        "window_size": None,
        "ipid": None,
        "tcp_options": None,
        "response_summary": "No response",
    }


def _base_analysis_result(probe_type, port, service):
    return {
        "probe_type": probe_type,
        "port": port,
        "service": service,
        "status": "unknown",
        "response_summary": "",
    }


# ---------------------------------------------------------------------------
# Field Extractors
# ---------------------------------------------------------------------------
def _extract_ip_fields(reply):
    if reply and reply.haslayer(IP):
        return reply[IP].ttl, reply[IP].id
    return None, None


def _extract_tcp_fields(reply):
    """
    Returns:
        (flags_str, window_size, options_list)
    """
    if not reply or not reply.haslayer(TCP):
        return None, None, None

    tcp = reply[TCP]

    try:
        flags = str(tcp.flags)
    except Exception:
        flags = "UNKNOWN"

    window = tcp.window
    options = list(tcp.options) if tcp.options else []

    return flags, window, options


def _set_common_tcp_fields(result, reply):
    ttl, ipid = _extract_ip_fields(reply)
    flags, window, options = _extract_tcp_fields(reply)

    result["ttl"] = ttl
    result["ipid"] = ipid
    result["flags"] = flags
    result["window_size"] = window
    result["tcp_options"] = options


# ---------------------------------------------------------------------------
# SYN Probe
# ---------------------------------------------------------------------------
def syn_probe(target, port, service, timeout=2):
    result = _base_result("TCP_SYN", port, service)

    try:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "filtered"
            result["response_summary"] = "No response — port filtered or host silent"
            return result

        _set_common_tcp_fields(result, reply)

        if reply.haslayer(TCP):
            flags = result["flags"]

            if flags and "S" in flags and "A" in flags:
                result["status"] = "open"
                result["response_summary"] = "SYN-ACK received — port open"
            elif flags and "R" in flags:
                result["status"] = "closed"
                result["response_summary"] = "RST received — port closed"
            else:
                result["status"] = "unexpected"
                result["response_summary"] = f"Unexpected TCP response: flags={flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "filtered_icmp"
            result["response_summary"] = "ICMP unreachable received — administratively filtered"

        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-TCP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ACK Probe
# ---------------------------------------------------------------------------
def ack_probe(target, port, service, timeout=2):
    result = _base_result("TCP_ACK", port, service)

    try:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="A")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "filtered"
            result["response_summary"] = "No response — stateful firewall likely present"
            return result

        _set_common_tcp_fields(result, reply)

        if reply.haslayer(TCP):
            flags = result["flags"]

            if flags and "R" in flags:
                result["status"] = "unfiltered"
                result["response_summary"] = "RST received — host reachable, filtering likely limited"
            else:
                result["status"] = "unexpected"
                result["response_summary"] = f"Unexpected TCP flags: {flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "filtered_icmp"
            result["response_summary"] = "ICMP unreachable received — filtering/firewall present"

        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-TCP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# NULL Probe
# ---------------------------------------------------------------------------
def null_probe(target, port, service, timeout=2):
    result = _base_result("TCP_NULL", port, service)

    try:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags=0x00)
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No response — open (Unix-like) or filtered"
            return result

        _set_common_tcp_fields(result, reply)

        if reply.haslayer(TCP):
            flags = result["flags"]

            if flags and "R" in flags:
                result["status"] = "responded_rst"
                result["response_summary"] = "RST received — closed port or malformed packet handled"
            else:
                result["status"] = "responded_other"
                result["response_summary"] = f"Unexpected TCP response to NULL probe: {flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "filtered_icmp"
            result["response_summary"] = "ICMP unreachable received — filtered"

        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-TCP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# FIN Probe
# ---------------------------------------------------------------------------
def fin_probe(target, port, service, timeout=2):
    result = _base_result("TCP_FIN", port, service)

    try:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="F")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No response — open (Unix-like) or filtered"
            return result

        _set_common_tcp_fields(result, reply)

        if reply.haslayer(TCP):
            flags = result["flags"]

            if flags and "R" in flags:
                result["status"] = "responded_rst"
                result["response_summary"] = "RST received — closed port"
            else:
                result["status"] = "responded_other"
                result["response_summary"] = f"Unexpected TCP response to FIN probe: {flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "filtered_icmp"
            result["response_summary"] = "ICMP unreachable received — filtered"

        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-TCP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# XMAS Probe
# ---------------------------------------------------------------------------
def xmas_probe(target, port, service, timeout=2):
    result = _base_result("TCP_XMAS", port, service)

    try:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="FPU")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No response — open (Unix-like) or filtered"
            return result

        _set_common_tcp_fields(result, reply)

        if reply.haslayer(TCP):
            flags = result["flags"]

            if flags and "R" in flags:
                result["status"] = "responded_rst"
                result["response_summary"] = "RST received — malformed packets not silently dropped"
            else:
                result["status"] = "responded_other"
                result["response_summary"] = f"Unexpected TCP response to XMAS probe: {flags}"

        elif reply.haslayer(ICMP):
            result["status"] = "filtered_icmp"
            result["response_summary"] = "ICMP unreachable received — filtered"

        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-TCP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ISN Entropy Analysis
# ---------------------------------------------------------------------------
def isn_entropy_analysis(target, port, service, count=6, timeout=2):
    result = {
        "probe_type": "ISN_ENTROPY",
        "port": port,
        "service": service,
        "isn_values": [],
        "isn_diffs": [],
        "entropy_score": None,
        "verdict": "unknown",
        "response_summary": "",
    }

    isns = []

    for _ in range(count):
        try:
            pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S", seq=0)
            reply = sr1(pkt, timeout=timeout)

            if reply and reply.haslayer(TCP):
                flags = str(reply[TCP].flags)
                if "S" in flags and "A" in flags:
                    isns.append(reply[TCP].seq)

        except Exception:
            pass

        time.sleep(0.3)

    result["isn_values"] = isns

    if len(isns) < 3:
        result["verdict"] = "insufficient_data"
        result["response_summary"] = f"Only {len(isns)} ISN samples collected — need an open responsive port"
        return result

    diffs = [abs(isns[i + 1] - isns[i]) for i in range(len(isns) - 1)]
    diffs = [d if d < 2**31 else 2**32 - d for d in diffs]

    result["isn_diffs"] = diffs

    if not diffs:
        result["verdict"] = "insufficient_data"
        result["response_summary"] = "Could not compute ISN differences"
        return result

    mean_diff = statistics.mean(diffs)

    try:
        cv = statistics.stdev(diffs) / mean_diff if mean_diff > 0 else 0
    except statistics.StatisticsError:
        cv = 0

    if mean_diff < 100_000 or cv < 0.1:
        entropy_score = round(min(cv, 0.3), 3)
        verdict = "low_entropy_predictable"
        summary = (
            f"ISN diffs are small/uniform (mean={int(mean_diff)}, CV={cv:.3f}). "
            "Sequence prediction may be feasible."
        )
    elif mean_diff < 1_000_000:
        entropy_score = round(min(0.3 + cv * 0.4, 0.7), 3)
        verdict = "medium_entropy"
        summary = (
            f"Moderate ISN randomness (mean={int(mean_diff)}, CV={cv:.3f}). "
            "Some predictability may exist."
        )
    else:
        entropy_score = round(min(0.7 + cv * 0.3, 1.0), 3)
        verdict = "high_entropy_random"
        summary = (
            f"High ISN randomness (mean={int(mean_diff)}, CV={cv:.3f}). "
            "Sequence prediction not feasible."
        )

    result["entropy_score"] = entropy_score
    result["verdict"] = verdict
    result["response_summary"] = summary

    return result


# ---------------------------------------------------------------------------
# SYN Cookie Detection
# ---------------------------------------------------------------------------
def syn_cookie_detection(target, port, service, count=6, timeout=2):
    result = {
        "probe_type": "SYN_COOKIE_DETECTION",
        "port": port,
        "service": service,
        "responses_received": 0,
        "syn_cookie_likely": None,
        "verdict": "unknown",
        "response_summary": "",
    }

    responses = 0

    for _ in range(count):
        try:
            pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
            reply = sr1(pkt, timeout=timeout)

            if reply and reply.haslayer(TCP):
                flags = str(reply[TCP].flags)
                if "S" in flags and "A" in flags:
                    responses += 1

        except Exception:
            pass

        time.sleep(0.1)

    result["responses_received"] = responses

    if responses == 0:
        result["syn_cookie_likely"] = None
        result["verdict"] = "port_not_open_or_filtered"
        result["response_summary"] = "No SYN-ACK received — cannot assess SYN cookie behavior"
    elif responses >= count - 1:
        result["syn_cookie_likely"] = True
        result["verdict"] = "syn_cookies_likely_active"
        result["response_summary"] = (
            f"Responded to {responses}/{count} rapid SYN probes — "
            "SYN cookie protection likely active."
        )
    elif responses >= count // 2:
        result["syn_cookie_likely"] = None
        result["verdict"] = "inconclusive"
        result["response_summary"] = (
            f"Partial responses ({responses}/{count}) — inconclusive. "
            "Possible rate limiting or partial SYN cookie behavior."
        )
    else:
        result["syn_cookie_likely"] = False
        result["verdict"] = "syn_cookies_absent_or_limited"
        result["response_summary"] = (
            f"Only {responses}/{count} SYN probes answered — "
            "backlog protection may be weak or absent."
        )

    return result