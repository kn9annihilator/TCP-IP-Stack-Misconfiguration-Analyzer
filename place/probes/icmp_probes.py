# probes/icmp_probes.py
#
# All ICMP-level probes.
#
# WHY EACH PROBE EXISTS:
#
#   Echo probe        — confirms host liveness; ICMP echo enabled = discoverable
#   Timestamp probe   — ICMP Type 13/14; leaks system uptime and clock skew
#   Rate limit test   — rapid echo burst; no rate limiting = ICMP flood feasibility

import time

from scapy.all import IP, ICMP, sr1, conf

conf.verb = 0


def _base_icmp_result(probe_type):
    return {
        "probe_type":       probe_type,
        "status":           "unknown",
        "ttl":              None,
        "ipid":             None,
        "round_trip_ms":    None,
        "response_summary": "No response",
    }


def _extract_ip_fields(reply):
    ttl  = reply["IP"].ttl if reply and reply.haslayer("IP") else None
    ipid = reply["IP"].id  if reply and reply.haslayer("IP") else None
    return ttl, ipid


# ---------------------------------------------------------------------------
# ICMP Echo Probe (Type 8 → expects Type 0 reply)
# Basic host liveness detection.
# If ICMP echo replies are enabled, the host is trivially discoverable.
# This is a configuration choice — many hardened systems disable echo replies.
# ---------------------------------------------------------------------------
def echo_probe(target, timeout=2):
    result = _base_icmp_result("ICMP_ECHO")
    try:
        pkt   = IP(dst=target) / ICMP(type=8, code=0)
        start = time.time()
        reply = sr1(pkt, timeout=timeout)
        rtt   = round((time.time() - start) * 1000, 2)

        if reply is None:
            result["status"]           = "no_reply"
            result["response_summary"] = "No ICMP echo reply — host may block ping or be down"
            return result

        result["ttl"], result["ipid"] = _extract_ip_fields(reply)
        result["round_trip_ms"]       = rtt

        if reply.haslayer(ICMP):
            t = reply[ICMP].type
            c = reply[ICMP].code
            if t == 0:
                result["status"]           = "reachable"
                result["response_summary"] = f"Echo reply received — RTT={rtt}ms, TTL={result['ttl']}"
            else:
                result["status"]           = "icmp_non_echo"
                result["response_summary"] = f"Unexpected ICMP type={t}, code={c}"
        else:
            result["status"]           = "unexpected_response"
            result["response_summary"] = "Non-ICMP response to echo probe"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied — run as root/Administrator"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ICMP Timestamp Probe (Type 13 → expects Type 14 reply)
#
# WHY IT MATTERS:
# ICMP timestamp replies contain the target's system time (milliseconds since midnight).
# From multiple timestamp replies you can:
#   1. Calculate approximate system uptime (compare with epoch)
#   2. Measure clock skew — useful for distinguishing VMs from physical hosts
#   3. Correlate identity across sessions (same clock = same device behind NAT)
#
# RFC 792 defines this as optional. Well-hardened systems disable it.
# Linux: disabled via iptables / nftables. Windows: disabled by default in modern versions.
# ---------------------------------------------------------------------------
def timestamp_probe(target, timeout=2):
    result = {
        "probe_type":          "ICMP_TIMESTAMP",
        "status":              "unknown",
        "ttl":                 None,
        "originate_time":      None,  # time sent by probe (our clock)
        "receive_time":        None,  # time target received it (target's clock)
        "transmit_time":       None,  # time target sent reply (target's clock)
        "clock_skew_ms":       None,  # estimated difference between our clock and theirs
        "response_summary":    "No response",
    }

    try:
        # ICMP Type 13: Timestamp Request
        # Fields: originate (our time), receive (filled by target), transmit (filled by target)
        our_time_ms = int((time.time() % 86400) * 1000)  # ms since midnight UTC
        pkt   = IP(dst=target) / ICMP(type=13, code=0,
                                       id=0x1234, seq=1,
                                       ts_ori=our_time_ms,
                                       ts_rx=0,
                                       ts_tx=0)
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"]           = "no_reply"
            result["response_summary"] = "No timestamp reply — likely disabled (good)"
            return result

        result["ttl"], _ = _extract_ip_fields(reply)

        if reply.haslayer(ICMP) and reply[ICMP].type == 14:
            ts_ori = reply[ICMP].ts_ori
            ts_rx  = reply[ICMP].ts_rx
            ts_tx  = reply[ICMP].ts_tx

            result["status"]         = "timestamp_reply_received"
            result["originate_time"] = ts_ori
            result["receive_time"]   = ts_rx
            result["transmit_time"]  = ts_tx

            # Clock skew: difference between our originate time and their receive time
            skew = ts_rx - ts_ori
            # Handle midnight wraparound (86400000 ms in a day)
            if skew > 43200000:
                skew -= 86400000
            elif skew < -43200000:
                skew += 86400000

            result["clock_skew_ms"]    = skew
            result["response_summary"] = (
                f"ICMP timestamp reply received — "
                f"originate={ts_ori}ms, receive={ts_rx}ms, transmit={ts_tx}ms, "
                f"clock_skew={skew}ms. Uptime/identity leakage possible."
            )
        else:
            result["status"]           = "unexpected_response"
            result["response_summary"] = "Received ICMP but not a timestamp reply"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ICMP Rate Limit Test
# Sends a rapid burst of ICMP echo requests and counts how many get responses.
#
# WHY IT MATTERS:
# Systems without ICMP rate limiting respond to every echo request.
# This means:
#   1. ICMP flood feasibility is higher (amplification potential)
#   2. The host can be used as a reflector in amplification attacks
#   3. Bandwidth exhaustion via ICMP becomes more feasible
#
# Linux: rate limiting via net.ipv4.icmp_ratelimit (default: 1000ms token bucket)
# Windows: typically responds to all echoes (no built-in rate limiting)
# A well-configured firewall limits inbound ICMP rate regardless.
# ---------------------------------------------------------------------------
def rate_limit_test(target, count=10, burst_delay=0.05, timeout=2):
    result = {
        "probe_type":        "ICMP_RATE_LIMIT",
        "probes_sent":       count,
        "responses_received": 0,
        "response_rate":     0.0,
        "rate_limit_detected": None,
        "verdict":           "unknown",
        "response_summary":  "",
    }

    responses = 0
    for i in range(count):
        try:
            pkt   = IP(dst=target) / ICMP(type=8, code=0, id=0x4444, seq=i)
            reply = sr1(pkt, timeout=timeout)
            if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                responses += 1
        except Exception:
            pass
        time.sleep(burst_delay)

    result["responses_received"] = responses
    rate = responses / count if count > 0 else 0.0
    result["response_rate"] = round(rate, 2)

    if responses == 0:
        result["rate_limit_detected"]  = None
        result["verdict"]              = "host_not_responding"
        result["response_summary"]     = "No ICMP echo replies — host blocks ICMP or is down"
    elif rate >= 0.9:
        result["rate_limit_detected"]  = False
        result["verdict"]              = "no_rate_limit_detected"
        result["response_summary"]     = (
            f"Responded to {responses}/{count} rapid probes ({rate*100:.0f}%). "
            "No ICMP rate limiting detected — flood feasibility: Higher."
        )
    elif rate >= 0.4:
        result["rate_limit_detected"]  = True
        result["verdict"]              = "rate_limiting_partial"
        result["response_summary"]     = (
            f"Partial responses ({responses}/{count}, {rate*100:.0f}%). "
            "Rate limiting appears active but not aggressive."
        )
    else:
        result["rate_limit_detected"]  = True
        result["verdict"]              = "rate_limiting_active"
        result["response_summary"]     = (
            f"Few responses ({responses}/{count}, {rate*100:.0f}%). "
            "Aggressive ICMP rate limiting active — flood feasibility: Lower."
        )

    return result


# ---------------------------------------------------------------------------
# Repeated ICMP Analysis
# Sends multiple echo probes with a short delay and collects IPID and TTL values.
# Used for:
#   - IPID sequence analysis (idle scan feasibility)
#   - TTL stability (OS fingerprinting confirmation)
#   - Average RTT measurement
# ---------------------------------------------------------------------------
def repeated_echo_analysis(target, count=5, timeout=2):
    result = {
        "probe_type":      "REPEATED_ICMP",
        "count":           count,
        "ttl_values":      [],
        "ipid_values":     [],
        "rtt_values_ms":   [],
        "avg_rtt_ms":      None,
        "ttl_stable":      False,
        "response_summary": "",
    }

    for _ in range(count):
        r = echo_probe(target, timeout=timeout)
        if r["ttl"]  is not None: result["ttl_values"].append(r["ttl"])
        if r["ipid"] is not None: result["ipid_values"].append(r["ipid"])
        if r["round_trip_ms"] is not None: result["rtt_values_ms"].append(r["round_trip_ms"])
        time.sleep(0.4)

    if result["rtt_values_ms"]:
        result["avg_rtt_ms"] = round(sum(result["rtt_values_ms"]) / len(result["rtt_values_ms"]), 2)

    if result["ttl_values"]:
        result["ttl_stable"] = len(set(result["ttl_values"])) == 1

    parts = []
    if result["ttl_values"]:
        parts.append(f"TTL values: {result['ttl_values']}")
    if result["ipid_values"]:
        parts.append(f"IPID values: {result['ipid_values']}")
    if result["avg_rtt_ms"]:
        parts.append(f"Avg RTT: {result['avg_rtt_ms']}ms")

    result["response_summary"] = " | ".join(parts) if parts else "No echo replies received"
    return result