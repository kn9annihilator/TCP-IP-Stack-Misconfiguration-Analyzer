# config.py
# Central configuration for TCP/IP Stack Misconfiguration Analyzer

PROJECT_TITLE = "Analysis of TCP/IP Stack Misconfigurations and Their Security Implications"

# --- Probe settings ---
TARGET_TIMEOUT       = 2     # seconds per probe
REPEAT_ICMP_COUNT    = 5     # probes for IPID/TTL stability analysis
ISN_SAMPLE_COUNT     = 6     # SYN probes for ISN entropy (need >= 5 meaningful diffs)
ICMP_RATE_TEST_COUNT = 10    # rapid ICMP burst for rate-limit detection
ICMP_BURST_DELAY     = 0.05  # 50ms between burst probes
SYN_COOKIE_TEST_COUNT = 6    # half-open SYNs to test backlog behavior

# --- Port definitions ---
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

PORT_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    8080: "HTTP-Alt",
}

# Ports that, if open, represent high offensive value
HIGH_RISK_PORTS = [21, 22, 23, 25, 139, 445]
LOW_RISK_PORTS  = [53, 80, 110, 143, 443, 8080]

# --- Weighted scoring model ---
# Each weight represents the offensive capability that misconfiguration enables.
# Higher = more dangerous from an attacker's perspective.
#
# Scale: 0-100 total risk budget
# These weights are used additively; final score is normalized to 0-10.

SCORE_WEIGHTS = {
    "isn_low_entropy":            15,  # enables session prediction / hijacking
    "no_syn_cookies":             12,  # SYN flood / DoS feasibility confirmed
    "ipid_predictable":           12,  # enables idle scan (anonymous port scanning)
    "malformed_flags_responded":   8,  # stateful firewall absent; filter evasion possible
    "open_high_risk_port":         8,  # per port (SSH/Telnet/SMB etc.)
    "icmp_timestamp_enabled":      7,  # uptime and clock skew leakage
    "icmp_no_rate_limit":          6,  # ICMP flood / amplification feasibility
    "os_fingerprinted":            5,  # OS identity confirmed; exploit selection enabled
    "ack_unfiltered":              5,  # firewall gap; stateless or misconfigured
    "icmp_echo_enabled":           4,  # host discovery confirmed
    "ttl_exposes_os":              3,  # passive fingerprinting via TTL
    "open_low_risk_port":          2,  # per port
    "tcp_options_fingerprint":     2,  # OS identity partially leaked via options
}

# Maximum possible raw score (sum of all weights at worst case)
# Used for normalization to 0-10
RAW_SCORE_CAP = 100