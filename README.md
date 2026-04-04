# TCP/IP Stack Misconfiguration Analyzer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

> **Research Project** — Analysis of TCP/IP Stack Misconfigurations and Their Security Implications  

A custom active probing tool that analyzes TCP/IP stack–level misconfigurations and abnormal protocol behaviors in networked systems. The tool assesses reconnaissance feasibility, OS fingerprinting potential, and denial-of-service susceptibility purely from protocol behavior — **no exploits, no CVEs required**.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Probe Modules](#probe-modules)
- [Scoring Model](#scoring-model)
- [Setup](#setup)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Research Context](#research-context)
- [Ethical Scope](#ethical-scope)
- [References](#references)

---

## Overview

Modern networked systems can be fingerprinted, mapped, and assessed for denial-of-service susceptibility without triggering a single CVE. The vulnerability lies in **how the TCP/IP stack responds to crafted packets** — behavior shaped by both the protocol design (RFC 793, RFC 792) and administrator configuration choices.

This tool actively probes a target host using crafted TCP and ICMP packets, analyzes the behavioral responses, and produces a unified offensive misconfiguration risk score.

**What it detects:**

| Misconfiguration | Attack Vector Enabled |
|---|---|
| Predictable ISN generation | Session prediction / TCP hijacking |
| No SYN cookie protection | SYN flood DoS feasibility |
| Sequential IPID | Idle scan (anonymous port scanning) |
| Malformed TCP flag responses | Firewall filter evasion |
| ICMP timestamp replies enabled | Uptime and clock skew leakage |
| No ICMP rate limiting | ICMP flood feasibility |
| OS fingerprint leakage | Targeted exploit selection |
| ACK probe not filtered | Stateful firewall gap |

---

## How It Works

The tool runs probes across 14 phases:

```
Phase 1   TCP SYN probes          Port state + TCP options collection
Phase 2   TCP ACK probes          Stateful firewall detection
Phase 3   Malformed flag probes   NULL / FIN / XMAS — filter evasion assessment
Phase 4   ISN entropy analysis    Sequence number randomness measurement
Phase 5   SYN cookie detection    DoS protection feasibility
Phase 6   ICMP echo probe         Host liveness and discoverability
Phase 7   ICMP timestamp probe    Uptime / clock skew leakage
Phase 8   ICMP rate limit test    Flood feasibility
Phase 9   Repeated ICMP           IPID collection for idle scan analysis
Phase 10  Fingerprinting          OS ID via TTL + window size + TCP options
Phase 11  Analysis                Findings mapped to named attack vectors
Phase 12  Scoring                 Weighted offensive risk score (0–10)
Phase 13  Mitigations             Prioritized remediation recommendations
Phase 14  Reports                 JSON + TXT output
```

---

## Project Structure

```
tcpip_analyzer/
│
├── main.py                    # Orchestrator — runs all phases in sequence
├── config.py                  # All constants: ports, timeouts, scoring weights
│
├── probes/
│   ├── tcp_probes.py          # SYN, ACK, NULL, FIN, XMAS, ISN analysis, SYN cookie
│   ├── icmp_probes.py         # Echo, Timestamp (Type 13), Rate limit, Repeated echo
│   └── fingerprint.py        # OS fingerprint, IPID entropy, TCP options parser
│
├── analysis/
│   ├── analyzer.py            # Maps findings to attack vectors
│   └── scorer.py              # Weighted scoring model + mitigation generator
│
└── reporter/
    └── generator.py           # JSON and TXT report generation
```

---

## Probe Modules

### `probes/tcp_probes.py`

| Function | Probe Type | What It Detects |
|---|---|---|
| `syn_probe()` | SYN → SYN-ACK / RST | Port state, TCP options, window size |
| `ack_probe()` | Unsolicited ACK | Stateful vs stateless firewall behavior |
| `null_probe()` | No-flag packet | Malformed packet filtering (absent = evasion possible) |
| `fin_probe()` | FIN without connection | RFC 793 compliance, filter bypass feasibility |
| `xmas_probe()` | FIN+PSH+URG | Same as NULL; different signature |
| `isn_entropy_analysis()` | Multiple SYN probes | ISN randomness via coefficient of variation |
| `syn_cookie_detection()` | Rapid SYN burst | SYN backlog exhaustion / syncookie protection |

### `probes/icmp_probes.py`

| Function | ICMP Type | What It Detects |
|---|---|---|
| `echo_probe()` | Type 8/0 | Host liveness, TTL, IPID, RTT |
| `timestamp_probe()` | Type 13/14 | Clock value leakage, uptime estimation |
| `rate_limit_test()` | Type 8 burst | ICMP rate limiting presence |
| `repeated_echo_analysis()` | Type 8 × N | IPID sequence collection, TTL stability |

### `probes/fingerprint.py`

| Function | Input | Output |
|---|---|---|
| `fingerprint_os()` | TTL, window size, TCP options | OS match with confidence level |
| `analyze_ipid_entropy()` | IPID value sequence | Sequential / incremental / randomized classification |
| `analyze_tcp_options()` | Options from SYN-ACK | Options order string, MSS, WScale, timestamp flag |

---

## Scoring Model

The scoring model is the novel contribution of this research. Rather than binary pass/fail, each confirmed misconfiguration adds a weight proportional to the offensive capability it enables. The raw score is normalized to **0–10**.

```
Factor                        Weight   Offensive Capability
─────────────────────────────────────────────────────────────
ISN low entropy                  15    Session prediction / hijacking
No SYN cookies                   12    SYN flood DoS feasibility
IPID predictable                 12    Idle scan / anonymous scanning
Malformed flags responded         8    Filter evasion techniques
Open high-risk port               8    Direct service attack surface (per port)
ICMP timestamp enabled            7    Uptime / identity leakage
ICMP no rate limiting             6    Flood / amplification feasibility
OS fingerprinted                  5    Targeted exploit selection
ACK unfiltered                    5    Stateful firewall gap
ICMP echo enabled                 4    Host discovery
TTL exposes OS                    3    Passive fingerprinting
Open low-risk port                2    Service exposure (per port)
TCP options fingerprint           2    Partial OS identity leakage
```

**Risk Bands:**

| Score | Risk Level |
|---|---|
| 0.0 – 2.0 | Low |
| 2.1 – 4.5 | Medium |
| 4.6 – 7.0 | High |
| 7.1 – 10.0 | Critical |

---

## Setup

### Prerequisites

- Python 3.8+
- Scapy 2.5+
- **Windows**: [Npcap](https://npcap.com/#download) (install with WinPcap API-compatible mode checked)
- **Linux**: Root privileges (`sudo`)

### Install

```bash
# Clone the repo
git clone https://github.com/yourusername/tcpip-stack-analyzer.git
cd tcpip-stack-analyzer

# Install dependency
pip install scapy
```

### Verify

```bash
python -c "from scapy.all import IP, TCP, ICMP; print('Scapy OK')"
```

---

## Usage

**Linux / Kali:**
```bash
sudo python main.py
```

**Windows (run terminal as Administrator):**
```bash
python main.py
```

You will be prompted for the target IP:
```
  Enter target IP address: 192.168.1.10
```

Reports are saved to `reports/` as both `.json` and `.txt`.

### Recommended Test Environment

Run exclusively against systems you own or have explicit written authorization to test. A controlled VM lab is recommended:

| VM | Role |
|---|---|
| Kali Linux | Attacker machine (run the tool here) |
| Ubuntu 22.04 | Target — default config |
| Windows 10/11 | Target — Windows stack behavior |
| FreeBSD / pfSense | Target — BSD stack behavior |
| Ubuntu (hardened) | Target — validate mitigations |

---

## Sample Output

```
============================================================
  Phase 12 — Scoring
============================================================
  RISK SCORE : 6.4 / 10
  RISK LEVEL : High

  Triggered factors (7):
    [ 12pt]  SYN cookie protection absent — only 1 responses to rapid SYNs
    [ 12pt]  IPID pattern: incremental_low_entropy — idle scan partially feasible
    [  8pt]  2 malformed TCP probes (NULL/FIN/XMAS) returned RST
    [  8pt]  Port 22 open — high-value service directly accessible
    [  5pt]  OS confirmed as Linux (kernel 3.x-5.x) (high confidence)
    [  4pt]  ICMP echo replies active — host trivially discoverable
    [  3pt]  TTL=64 confirms OS family — passive fingerprinting enabled
```

---

## Research Context

This project is part of undergraduate research at Sharda University targeting the following research gap:

> Existing tools (Nmap, p0f) identify OS. This tool identifies **misconfiguration risk** from the same behavioral signals — and scores it offensively as a unified risk model.

No existing standalone tool produces: *"This host's TCP stack behavior makes it X% feasible to fingerprint, susceptible to SYN exhaustion, and usable for idle scan"* as a single normalized score. That unified offensive scoring model is the original contribution.

**Research paper in progress** — findings will be submitted to IEEE Xplore.

---

## Ethical Scope

This tool is designed for:
- Controlled lab environments (VMs you own)
- Systems you have explicit written authorization to test
- Academic research and educational demonstration

It is **not** designed for and must **not** be used against:
- Production systems without authorization
- Systems on public networks
- Any target where you do not have legal permission

All probes measure **feasibility** — they do not execute actual attacks.

---

## References

- RFC 793 — Transmission Control Protocol
- RFC 792 — Internet Control Message Protocol
- RFC 1122 — Requirements for Internet Hosts
- RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations
- RFC 6528 — Defending Against Sequence Number Attacks
- Gordon Lyon — *Nmap Network Scanning* (nmap.org/book)
- p0f v3 — Passive OS Fingerprinting Tool