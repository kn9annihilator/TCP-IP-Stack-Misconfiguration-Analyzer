# probes/tcp_probes.py
#
# All TCP-level probes.
# Each probe returns a dict with consistent keys so the analyzer can process
# results uniformly regardless of probe type.
#
# WHY EACH PROBE EXISTS (offensive rationale):
#
#   SYN probe     — standard port state detection; open/closed/filtered
#   ACK probe     — firewall detection; stateless firewall passes ACK, stateful drops it
#   NULL probe    — no flags; RFC 793 undefined behavior; reveals OS differences
#   FIN probe     — RFC says closed port returns RST; open port drops silently (on Unix)
#   XMAS probe    — FIN+PSH+URG; same RFC ambiguity; most firewalls drop these
#   ISN analysis  — measures sequence number entropy; low entropy = session prediction risk
#   SYN cookie    — tests whether SYN flood protection is active

import time
import math
import statistics

from scapy.all import IP, TCP, RandShort, sr1, conf

conf.verb = 0


def _base_result(probe_type, port, service):
    return {
        "probe_type":        probe_type,
        "port":              port,
        "service":           service,
        "status":            "unknown",
        "flags":             None,
        "ttl":               None,
        "window_size":       None,
        "ipid":              None,
        "tcp_options":       None,
        "response_summary":  "No response",
    }


def _extract_ip_fields(reply):
    ttl  = reply["IP"].ttl  if reply and reply.haslayer("IP")  else None
    ipid = reply["IP"].id   if reply and reply.haslayer("IP")  else None
    return ttl, ipid


def _extract_tcp_fields(reply):
    """
    Returns (flags_str, window_size, options_list).
    TCP options like MSS, SACK, Timestamp, Window Scaling are key fingerprinting signals.
    Different OSes negotiate different option sets in a different order.
    """
    if not reply or not reply.haslayer(TCP):
        return None, None, None
    tcp = reply[TCP]
    try:
        flags = str(tcp.flags)
    except Exception:
        flags = "UNKNOWN"
    window  = tcp.window
    options = [(opt[0], opt[1]) for opt in tcp.options] if tcp.options else []
    return flags, window, options


# ---------------------------------------------------------------------------
# SYN Probe
# Sends a SYN packet. Expects SYN-ACK (open), RST (closed), or no reply (filtered).
# Also extracts TCP options from SYN-ACK — these are the OS fingerprinting signals.
# ---------------------------------------------------------------------------
def syn_probe(target, port, service, timeout=2):
    result = _base_result("TCP_SYN", port, service)
    try:
        pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "filtered"
            result["response_summary"] = "No response — port filtered or host silent"
            return result

        ttl, ipid = _extract_ip_fields(reply)
        result["ttl"]  = ttl
        result["ipid"] = ipid

        flags, window, options = _extract_tcp_fields(reply)
        result["flags"]       = flags
        result["window_size"] = window
        result["tcp_options"] = options

        if flags and "S" in flags and "A" in flags:
            result["status"] = "open"
            result["response_summary"] = "SYN-ACK received — port open"
        elif flags and "R" in flags:
            result["status"] = "closed"
            result["response_summary"] = "RST received — port closed"
        elif reply.haslayer("ICMP"):
            result["status"] = "filtered_icmp"
            result["response_summary"] = "ICMP unreachable received — administratively filtered"
        else:
            result["status"] = "unexpected"
            result["response_summary"] = f"Unexpected response: flags={flags}"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied — run as root/Administrator"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ACK Probe
# Sends an unsolicited ACK (no prior connection).
# Stateful firewall: drops it silently (filtered).
# Stateless firewall / no firewall: RST returned (unfiltered).
# This reveals whether stateful packet inspection is in place.
# ---------------------------------------------------------------------------
def ack_probe(target, port, service, timeout=2):
    result = _base_result("TCP_ACK", port, service)
    try:
        pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="A")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "filtered"
            result["response_summary"] = "No response — stateful firewall likely present"
            return result

        ttl, ipid       = _extract_ip_fields(reply)
        result["ttl"]   = ttl
        result["ipid"]  = ipid
        flags, window, options = _extract_tcp_fields(reply)
        result["flags"] = flags

        if flags and "R" in flags:
            result["status"] = "unfiltered"
            result["response_summary"] = "RST received — host reachable, limited stateful filtering"
        else:
            result["status"] = "unexpected"
            result["response_summary"] = f"Unexpected flags: {flags}"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# NULL Probe
# Sends a TCP packet with NO flags set (flags=0x00).
# RFC 793 does not define behavior for this case.
# Linux/BSD: closed ports return RST; open ports are silent.
# Windows: RST on both open and closed (doesn't distinguish).
# A response to NULL means no stateful firewall is blocking malformed packets.
# ---------------------------------------------------------------------------
def null_probe(target, port, service, timeout=2):
    result = _base_result("TCP_NULL", port, service)
    try:
        pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags=0x00)
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No response — open (Unix) or filtered"
            return result

        ttl, ipid = _extract_ip_fields(reply)
        result["ttl"]  = ttl
        result["ipid"] = ipid
        flags, _, _ = _extract_tcp_fields(reply)
        result["flags"] = flags

        if flags and "R" in flags:
            result["status"] = "responded_rst"
            result["response_summary"] = "RST to NULL probe — closed port; malformed packets not filtered"
        else:
            result["status"] = "responded_other"
            result["response_summary"] = f"Unexpected response to NULL probe: {flags}"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# FIN Probe
# Sends a TCP FIN with no prior connection.
# RFC 793: closed port should return RST. Open port on Unix: silent drop.
# Windows: returns RST regardless (doesn't follow RFC for this case).
# Used to bypass simple packet filters that only block SYN packets.
# ---------------------------------------------------------------------------
def fin_probe(target, port, service, timeout=2):
    result = _base_result("TCP_FIN", port, service)
    try:
        pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="F")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No response — possibly open (Unix behavior) or filtered"
            return result

        ttl, ipid = _extract_ip_fields(reply)
        result["ttl"]  = ttl
        result["ipid"] = ipid
        flags, _, _ = _extract_tcp_fields(reply)
        result["flags"] = flags

        if flags and "R" in flags:
            result["status"] = "responded_rst"
            result["response_summary"] = "RST to FIN — closed port confirms RFC 793 behavior; filter absent"
        else:
            result["status"] = "responded_other"
            result["response_summary"] = f"Unexpected response to FIN: {flags}"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# XMAS Probe
# Sends FIN + PSH + URG simultaneously (flags=0x29).
# Named "XMAS" because all bits light up like a Christmas tree.
# RFC 793 undefined behavior — same logic as NULL probe.
# Well-configured systems with stateful firewalls drop these silently.
# A response confirms malformed packet filtering is absent.
# ---------------------------------------------------------------------------
def xmas_probe(target, port, service, timeout=2):
    result = _base_result("TCP_XMAS", port, service)
    try:
        pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="FPU")
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            result["status"] = "no_response"
            result["response_summary"] = "No response — open (Unix) or filtered/firewalled"
            return result

        ttl, ipid = _extract_ip_fields(reply)
        result["ttl"]  = ttl
        result["ipid"] = ipid
        flags, _, _ = _extract_tcp_fields(reply)
        result["flags"] = flags

        if flags and "R" in flags:
            result["status"] = "responded_rst"
            result["response_summary"] = "RST to XMAS probe — malformed packets not filtered"
        else:
            result["status"] = "responded_other"
            result["response_summary"] = f"Unexpected response to XMAS: {flags}"

    except PermissionError:
        result["status"]           = "error"
        result["response_summary"] = "Permission denied"
    except Exception as e:
        result["status"]           = "error"
        result["response_summary"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# ISN Entropy Analysis
# Sends multiple SYN probes to an open port with delays between them.
# Collects the ISN (Initial Sequence Number) from each SYN-ACK.
# Calculates entropy/predictability of the ISN sequence.
#
# WHY IT MATTERS:
# If ISN is predictable, an attacker can:
# - Predict sequence numbers and inject data into a TCP stream
# - Perform blind TCP spoofing attacks
# - Enable session hijacking without being on the network path
#
# Modern OS kernels use cryptographic ISN generation (RFC 6528).
# Older or misconfigured stacks use time-based or sequential ISNs.
# ---------------------------------------------------------------------------
def isn_entropy_analysis(target, port, service, count=6, timeout=2):
    result = {
        "probe_type":       "ISN_ENTROPY",
        "port":             port,
        "service":          service,
        "isn_values":       [],
        "isn_diffs":        [],
        "entropy_score":    None,   # 0.0 (fully predictable) to 1.0 (random)
        "verdict":          "unknown",
        "response_summary": "",
    }

    isns = []
    for i in range(count):
        try:
            pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S", seq=0)
            reply = sr1(pkt, timeout=timeout)
            if reply and reply.haslayer(TCP) and "S" in str(reply[TCP].flags):
                isns.append(reply[TCP].ack - 1)  # server's ISN is in ack-1 of our probe
                # Actually, server ISN is in reply[TCP].seq
                isns[-1] = reply[TCP].seq
        except Exception:
            pass
        time.sleep(0.3)

    result["isn_values"] = isns

    if len(isns) < 3:
        result["verdict"]          = "insufficient_data"
        result["response_summary"] = f"Only {len(isns)} ISN samples collected — need open port"
        return result

    # Calculate differences between consecutive ISNs
    diffs = [abs(isns[i+1] - isns[i]) for i in range(len(isns)-1)]
    # Handle 32-bit wraparound
    diffs = [d if d < 2**31 else 2**32 - d for d in diffs]
    result["isn_diffs"] = diffs

    if not diffs:
        result["verdict"]          = "insufficient_data"
        result["response_summary"] = "Could not compute ISN differences"
        return result

    mean_diff = statistics.mean(diffs)
    
    # Coefficient of variation: low CV = predictable, high CV = random
    # Also check absolute magnitude: very small diffs = time-based sequential ISN
    try:
        cv = statistics.stdev(diffs) / mean_diff if mean_diff > 0 else 0
    except Exception:
        cv = 0

    # Entropy score heuristic:
    # mean_diff < 100,000   → extremely low entropy (sequential/time-based)
    # CV < 0.1              → differences are too uniform (predictable pattern)
    # Otherwise scale by magnitude and variance
    
    if mean_diff < 100_000 or cv < 0.1:
        entropy_score = round(min(cv, 0.3), 3)
        verdict = "low_entropy_predictable"
        summary = (f"ISN diffs are small/uniform (mean={int(mean_diff)}, CV={cv:.3f}). "
                   "Sequence prediction feasible.")
    elif mean_diff < 1_000_000:
        entropy_score = round(min(0.3 + cv * 0.4, 0.7), 3)
        verdict = "medium_entropy"
        summary = (f"Moderate ISN randomness (mean={int(mean_diff)}, CV={cv:.3f}). "
                   "Some prediction feasibility.")
    else:
        entropy_score = round(min(0.7 + cv * 0.3, 1.0), 3)
        verdict = "high_entropy_random"
        summary = (f"High ISN randomness (mean={int(mean_diff)}, CV={cv:.3f}). "
                   "Sequence prediction not feasible.")

    result["entropy_score"]    = entropy_score
    result["verdict"]          = verdict
    result["response_summary"] = summary
    return result


# ---------------------------------------------------------------------------
# SYN Cookie Detection
# Tests whether the target's SYN backlog protection is active.
#
# METHOD:
# 1. Send SYN_COOKIE_TEST_COUNT half-open SYNs quickly (never completing handshake)
# 2. After filling what would be a small SYN queue, send one more SYN
# 3. If we still get a SYN-ACK → SYN cookies likely active (queue never truly fills)
# 4. If no response → backlog may be exhausted, no SYN cookie protection
#
# NOTE: This is a behavioral inference, not a guaranteed detection.
# SYN cookies produce non-standard ISNs (encoded hash), which is a secondary signal.
# ---------------------------------------------------------------------------
def syn_cookie_detection(target, port, service, count=6, timeout=2):
    result = {
        "probe_type":        "SYN_COOKIE_DETECTION",
        "port":              port,
        "service":           service,
        "responses_received": 0,
        "syn_cookie_likely": None,
        "verdict":           "unknown",
        "response_summary":  "",
    }

    if result["port"] not in [80, 443, 22, 21, 25]:
        # Only test on ports likely to be open
        pass

    responses = 0
    for _ in range(count):
        try:
            pkt   = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
            reply = sr1(pkt, timeout=1)
            if reply and reply.haslayer(TCP) and "S" in str(reply[TCP].flags):
                responses += 1
        except Exception:
            pass
        time.sleep(0.1)

    result["responses_received"] = responses

    if responses == 0:
        result["syn_cookie_likely"]  = None
        result["verdict"]            = "port_not_open_or_filtered"
        result["response_summary"]   = "No SYN-ACK received — cannot assess SYN cookie status"
    elif responses >= count - 1:
        result["syn_cookie_likely"]  = True
        result["verdict"]            = "syn_cookies_likely_active"
        result["response_summary"]   = (
            f"Responded to {responses}/{count} rapid SYN probes — "
            "SYN cookie protection likely active. SYN flood feasibility: Low."
        )
    elif responses >= count // 2:
        result["syn_cookie_likely"]  = None
        result["verdict"]            = "inconclusive"
        result["response_summary"]   = (
            f"Partial responses ({responses}/{count}) — inconclusive. "
            "May have rate limiting or partial SYN cookie support."
        )
    else:
        result["syn_cookie_likely"]  = False
        result["verdict"]            = "syn_cookies_absent_or_limited"
        result["response_summary"]   = (
            f"Only {responses}/{count} SYN probes answered — "
            "SYN backlog may be limited. SYN flood feasibility: Higher."
        )

    return result