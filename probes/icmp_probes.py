# probes/icmp_probes.py
#
# ICMP-level probes for the TCP/IP Stack Misconfiguration Analyzer.
# These probes help detect:
# - Host reachability
# - ICMP timestamp exposure
# - ICMP rate limiting
# - Repeated ICMP response behavior

import time
import statistics

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
from scapy.config import conf

conf.verb = 0


# ---------------------------------------------------------------------------
# Common Result Template
# ---------------------------------------------------------------------------
def _base_result(probe_type):
    return {
        "probe_type": probe_type,
        "status": "unknown",
        "ttl": None,
        "ipid": None,
        "icmp_type": None,
        "icmp_code": None,
        "response_time_ms": None,
        "response_summary": "No response",
    }


def _extract_ip_fields(reply):
    if reply and reply.haslayer(IP):
        return reply[IP].ttl, reply[IP].id
    return None, None


def _extract_icmp_fields(reply):
    if reply and reply.haslayer(ICMP):
        return reply[ICMP].type, reply[ICMP].code
    return None, None


# ---------------------------------------------------------------------------
# ICMP Echo Probe
# Standard ping-like request to test host reachability.
# ---------------------------------------------------------------------------
def echo_probe(target, timeout=2):
    result = _base_result("ICMP_ECHO")

    try:
        pkt = IP(dst=target) / ICMP(type=8)  # Echo Request
        start = time.time()
        reply = sr1(pkt, timeout=timeout)
        end = time.time()

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No ICMP Echo Reply received"
            return result

        result["response_time_ms"] = round((end - start) * 1000, 2)
        result["ttl"], result["ipid"] = _extract_ip_fields(reply)
        result["icmp_type"], result["icmp_code"] = _extract_icmp_fields(reply)

        if reply.haslayer(ICMP):
            if reply[ICMP].type == 0:
                result["status"] = "reachable"
                result["response_summary"] = "ICMP Echo Reply received — host reachable"
            elif reply[ICMP].type == 3:
                result["status"] = "unreachable"
                result["response_summary"] = "ICMP Destination Unreachable received"
            else:
                result["status"] = "unexpected"
                result["response_summary"] = (
                    f"Unexpected ICMP response: type={reply[ICMP].type}, code={reply[ICMP].code}"
                )
        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-ICMP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ICMP Timestamp Probe
# Sends ICMP Timestamp Request (Type 13).
# If the target replies with Type 14, it leaks clock/timestamp info.
# ---------------------------------------------------------------------------
def timestamp_probe(target, timeout=2):
    result = _base_result("ICMP_TIMESTAMP")

    try:
        pkt = IP(dst=target) / ICMP(type=13, code=0)
        start = time.time()
        reply = sr1(pkt, timeout=timeout)
        end = time.time()

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No ICMP Timestamp Reply received"
            return result

        result["response_time_ms"] = round((end - start) * 1000, 2)
        result["ttl"], result["ipid"] = _extract_ip_fields(reply)
        result["icmp_type"], result["icmp_code"] = _extract_icmp_fields(reply)

        if reply.haslayer(ICMP):
            if reply[ICMP].type == 14:
                result["status"] = "timestamp_exposed"
                result["response_summary"] = (
                    "ICMP Timestamp Reply received — host may expose system clock information"
                )
            elif reply[ICMP].type == 3:
                result["status"] = "blocked_or_unreachable"
                result["response_summary"] = "ICMP Destination Unreachable received"
            else:
                result["status"] = "unexpected"
                result["response_summary"] = (
                    f"Unexpected ICMP response: type={reply[ICMP].type}, code={reply[ICMP].code}"
                )
        else:
            result["status"] = "unexpected"
            result["response_summary"] = "Unexpected non-ICMP response"

    except PermissionError:
        result["status"] = "error"
        result["response_summary"] = "Permission denied — run as Administrator/root"
    except Exception as e:
        result["status"] = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ICMP Rate Limit Test
# Sends multiple ICMP Echo Requests quickly and measures how many replies arrive.
# Helps infer ICMP response throttling / rate limiting.
# ---------------------------------------------------------------------------
def rate_limit_test(target, count=6, timeout=1):
    result = {
        "probe_type": "ICMP_RATE_LIMIT",
        "sent": count,
        "received": 0,
        "loss_percent": None,
        "avg_rtt_ms": None,
        "verdict": "unknown",
        "response_summary": "",
    }

    rtts = []
    received = 0

    for _ in range(count):
        try:
            pkt = IP(dst=target) / ICMP(type=8)
            start = time.time()
            reply = sr1(pkt, timeout=timeout)
            end = time.time()

            if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                received += 1
                rtts.append((end - start) * 1000)

        except Exception:
            pass

        time.sleep(0.1)

    result["received"] = received
    result["loss_percent"] = round(((count - received) / count) * 100, 2)

    if rtts:
        result["avg_rtt_ms"] = round(statistics.mean(rtts), 2)

    if received == count:
        result["verdict"] = "no_rate_limit_detected"
        result["response_summary"] = (
            f"Received {received}/{count} replies — no obvious ICMP rate limiting detected"
        )
    elif received >= count // 2:
        result["verdict"] = "possible_rate_limiting"
        result["response_summary"] = (
            f"Received {received}/{count} replies — possible ICMP throttling or partial filtering"
        )
    elif received > 0:
        result["verdict"] = "strong_rate_limiting_or_filtering"
        result["response_summary"] = (
            f"Received only {received}/{count} replies — likely ICMP rate limiting or filtering"
        )
    else:
        result["verdict"] = "fully_blocked_or_unreachable"
        result["response_summary"] = (
            "No ICMP Echo Replies received — ICMP may be blocked or host unreachable"
        )

    return result


# ---------------------------------------------------------------------------
# Repeated Echo Analysis
# Sends multiple pings and checks TTL/IPID consistency for stack behavior.
# Useful for lightweight fingerprinting / anomaly observation.
# ---------------------------------------------------------------------------
def repeated_echo_analysis(target, count=5, timeout=1):
    result = {
        "probe_type": "ICMP_REPEATED_ECHO_ANALYSIS",
        "ttl_values": [],
        "ipid_values": [],
        "ttl_stable": None,
        "ipid_monotonic": None,
        "verdict": "unknown",
        "response_summary": "",
    }

    ttl_values = []
    ipid_values = []

    for _ in range(count):
        try:
            pkt = IP(dst=target) / ICMP(type=8)
            reply = sr1(pkt, timeout=timeout)

            if reply and reply.haslayer(IP) and reply.haslayer(ICMP):
                if reply[ICMP].type == 0:
                    ttl_values.append(reply[IP].ttl)
                    ipid_values.append(reply[IP].id)

        except Exception:
            pass

        time.sleep(0.2)

    result["ttl_values"] = ttl_values
    result["ipid_values"] = ipid_values

    if len(ttl_values) < 2:
        result["verdict"] = "insufficient_data"
        result["response_summary"] = "Too few ICMP replies received for repeated echo analysis"
        return result

    ttl_stable = len(set(ttl_values)) == 1
    ipid_monotonic = all(
        ipid_values[i] <= ipid_values[i + 1]
        for i in range(len(ipid_values) - 1)
    ) if len(ipid_values) >= 2 else None

    result["ttl_stable"] = ttl_stable
    result["ipid_monotonic"] = ipid_monotonic

    if ttl_stable and ipid_monotonic:
        result["verdict"] = "stable_stack_behavior"
        result["response_summary"] = (
            "TTL remained stable and IPID progression appears monotonic"
        )
    elif ttl_stable:
        result["verdict"] = "stable_ttl_variable_ipid"
        result["response_summary"] = (
            "TTL remained stable but IPID behavior varied"
        )
    else:
        result["verdict"] = "variable_behavior"
        result["response_summary"] = (
            "TTL/IPID values varied across repeated ICMP replies"
        )

    return result