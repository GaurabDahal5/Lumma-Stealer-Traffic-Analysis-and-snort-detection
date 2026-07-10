# Lumma stealer traffic analysis and snort detection

SOC Portfolio Project | Analyst: Gaurab Dahal | January 2026

> Repository type: This is an evidence and documentation portfolio. It contains analysis write-ups, screenshot evidence, Snort rules, IOC exports, and a payload decoder script. The raw PCAP is not included — download it separately to reproduce the analysis.

---

## Table of Contents

- [What This Project Is](#what-this-project-is)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Deliverables](#deliverables)
- [The Victim](#the-victim-extracted-from-pcap)
- [C2 Infrastructure](#c2-infrastructure)
- [Payload Analysis](#what-lumma-actually-sent--fingerprints-not-credentials)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Snort Rules](#snort-rules)
- [Detection Results](#detection-results)
- [How I Did the Analysis](#how-i-did-the-analysis)
- [Key Commands](#key-commands-used)
- [Evidence Index](#evidence-index)
- [Tools Used](#tools-used)

---

## What This Project Is

Real-world malware network traffic analysis. I analyzed a Lumma Stealer capture using Wireshark and tshark, decoded the exfiltrated payloads, mapped attacker behavior to MITRE ATT&CK, and validated detection logic with Snort evidence.

Malware: Lumma Stealer (Infostealer-as-a-Service)  
PCAP: `2026-01-31-traffic-analysis-exercise.pcap` (external — not in repo)  
Source: [malware-traffic-analysis.net](https://malware-traffic-analysis.net)  
Result: 59 Snort alerts confirmed on PCAP replay

Screenshot evidence is organized into four folders. The full written report is in [`reports/FINAL_REPORT.md`](reports/FINAL_REPORT.md) (Markdown) and [`reports/final.docx`](reports/final.docx) (Word).

---

## Quick Start

### 1. Download the PCAP

Obtain `2026-01-31-traffic-analysis-exercise.pcap` from [malware-traffic-analysis.net](https://malware-traffic-analysis.net) and save it to:

```
pcaps/2026-01-31-traffic-analysis-exercise.pcap
```

### 2. Install tools (Ubuntu 22.04 lab)

```bash
sudo apt update
sudo apt install -y wireshark tshark tcpdump snort python3
```

### 3. Deploy Snort rules

```bash
sudo cp rules/lumma.rules /etc/snort/rules/local.rules
# Or use the improved version:
sudo cp rules/lumma_improved.rules /etc/snort/rules/local.rules
sudo snort -c /etc/snort/snort.conf -T
```

### 4. Replay PCAP through Snort

```bash
mkdir -p analysis
sudo snort -r pcaps/2026-01-31-traffic-analysis-exercise.pcap \
  -c /etc/snort/snort.conf -A console -q 2>&1 | tee analysis/snort_alerts.txt
```

### 5. Decode exported HTTP payloads

Export POST bodies from Wireshark (File → Export Objects → HTTP), then:

```bash
python3 scripts/decode_payload.py set_agentChromeact=log* -o analysis/chrome_decoded.txt
python3 scripts/decode_payload.py set_agentEdgeact=log* -o analysis/edge_decoded.txt
```

---

## Project Structure

```
PROJECT/
├── analysis/                          # Working outputs (created during replay)
│   └── README.md
├── Basic recon & DNSHTTP filtering/     # 13 screenshots — PCAP recon & HTTP isolation
├── Decode and exfiltration evidence/  # 4 screenshots — payload decoding
├── data/
│   ├── detection_results.csv          # Snort alert counts by SID
│   ├── iocs.csv                       # IOC export (SIEM-ready)
│   └── iocs.json                      # Same IOCs in JSON format
├── docs/
│   └── EVIDENCE_INDEX.md              # Catalog of all 33 screenshots
├── reports/
│   ├── FINAL_REPORT.md                # Full incident response report
│   └── final.docx                     # Same report (Word format)
├── rules/
│   ├── lumma.rules                    # Original Snort rules (4 rules)
│   └── lumma_improved.rules           # Tuned rules — reduced false positives
├── scripts/
│   └── decode_payload.py              # URL-decode & JSON-parse exfil payloads
├── snort rules/                       # 6 screenshots — rule validation & replay
├── SOC Incident Response Lumma Malware/  # 10 screenshots — victim ID & IR evidence
├── traffic analysis using snort rules and snort/
│   └── Project Title.txt              # Project objective & workflow diagram
├── final.docx                         # Legacy copy (also in reports/)
└── README.md
```

---

## Deliverables

| File | Purpose |
|---|---|
| [`reports/FINAL_REPORT.md`](reports/FINAL_REPORT.md) | Complete incident response report |
| [`reports/final.docx`](reports/final.docx) | Same report in Word format |
| [`data/iocs.csv`](data/iocs.csv) / [`data/iocs.json`](data/iocs.json) | Machine-readable IOC exports |
| [`data/detection_results.csv`](data/detection_results.csv) | Snort detection summary |
| [`rules/lumma.rules`](rules/lumma.rules) | Deployable Snort rules |
| [`rules/lumma_improved.rules`](rules/lumma_improved.rules) | Improved rules with lower noise |
| [`scripts/decode_payload.py`](scripts/decode_payload.py) | Payload decoder script |
| [`docs/EVIDENCE_INDEX.md`](docs/EVIDENCE_INDEX.md) | Screenshot catalog |

---

## The Victim (Extracted From PCAP)

| Field | Value | How I Found It |
|---|---|---|
| IP Address | 10.1.21.58 | DHCP + HTTP traffic |
| MAC Address | 00:04:c1:be:8c:d4 | Ethernet / DHCP |
| Hostname | DESKTOP-ES9F3ML | DHCP Option 12 |
| Username | gwyatt | Kerberos AS-REQ |
| Full Name | Gabriel Wyatt | SAMR QueryUserInfo |
| Domain | WIN11OFFICE | Kerberos |
| Operating System | Windows NT 10.0 x64 | HTTP User-Agent |
| Last Logon | Jan 28, 2026 | SAMR |

Four independent protocols (DHCP, NBNS, Kerberos, SAMR) all agree on this identity.

![Full Name Confirmed via SAMR](SOC%20Incident%20Response%20Lumma%20Malware/full%20name%20of%20the%20host%20.png)

---

## C2 Infrastructure

| IOC | Value |
|---|---|
| C2 Domain | whitepepper.su (.su = Soviet Union TLD) |
| C2 IP | 153.92.1.49 |
| C2 URI | /api/set_agent |
| Bot ID | 3BF67EC05320C5729578BE4C0ADF174C |
| Auth Token | 842e2802df0f0a06b4ed51f12f4387e761523b |

![C2 IP Confirmed](Basic%20recon%20%26%20DNSHTTP%20filtering/08_c2_ip_confirmed.png)

Full IOC table: [`data/iocs.csv`](data/iocs.csv)

---

## What Lumma Actually Sent — Fingerprints, Not Credentials

Two POST requests went out — one from Chrome (8,023 bytes), one from Edge (7,975 bytes) — 7 seconds apart. That gap is too fast for manual browser switching; it's automated collection looping through installed browsers.

Because this build of Lumma skipped HTTPS, both payloads were in cleartext. Decoding showed:

- Full browser hardware fingerprint (GPU, CPU cores, screen resolution)
- Canvas fingerprint (unique per hardware)
- Anti-sandbox checks: `webdriver:false` + 12-core CPU check
- Font list, audio hardware, network connection type

Important: These payloads are device/browser fingerprints, not stolen passwords. Credential theft from Chrome's `Login Data` SQLite file happens as a local disk read and would not appear in this network capture.

![Chrome Decoded Fingerprint](Decode%20and%20exfiltration%20evidence/40_chrome_decode_canvas_network.png)

---

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1071.001 | Application Layer Protocol: Web | HTTP beaconing to whitepepper.su/api/set_agent |
| T1041 | Exfiltration Over C2 Channel | Two POST requests, 8KB+ each |
| T1555.003 | Credentials from Web Browsers | Chrome + Edge profiles targeted |
| T1082 | System Information Discovery | GPU, CPU, screen, OS profiled |
| T1497.001 | Virtualization/Sandbox Evasion | webdriver:false + 12-core CPU check |
| T1119 | Automated Collection | Chrome → Edge, 7 seconds apart |
| T1016 | System Network Configuration Discovery | Connection type/speed in payload |
| T1033 | System Owner/User Discovery | Bot ID tags victim across sessions |

Tactics not claimed — no packet evidence: Initial Access, Execution, Persistence, Lateral Movement.

---

## Snort Rules

Original rules: [`rules/lumma.rules`](rules/lumma.rules)

```
alert tcp any any -> 153.92.1.49 80 (msg:"Lumma C2 IP"; sid:1000001; rev:1;)
alert tcp any any -> any 80 (msg:"Lumma Domain"; content:"whitepepper.su"; sid:1000002; rev:1;)
alert tcp any any -> any 80 (msg:"Lumma URI"; content:"/api/set_agent"; sid:1000003; rev:1;)
alert tcp any any -> any 80 (msg:"Lumma POST"; content:"POST"; sid:1000004; rev:1;)
```

Improved rules (reduced false positives): [`rules/lumma_improved.rules`](rules/lumma_improved.rules)

![Snort Rule Validation](snort%20rules/snort%20rules%20validated%20successfully1.png)

---

## Detection Results

```bash
sudo snort -r pcaps/2026-01-31-traffic-analysis-exercise.pcap -c /etc/snort/snort.conf -A console -q
```

| Rule SID | Name | Alerts | Assessment |
|---|---|---|---|
| 1000001 | Lumma C2 IP | 45 | Noisy — fires on every TCP handshake |
| 1000002 | Lumma Domain | 6 | Clean — domain match only |
| 1000003 | Lumma URI | 6 | Clean — beacon URI match |
| 1000004 | Lumma POST Exfil | 2 | Precise — Chrome + Edge exfil events |
| TOTAL | | 59 | Detection confirmed |

![Snort Alert Count](snort%20rules/total%20alert%20counts.png)

Known weaknesses:
- Rule 1000001: fires on every SYN/ACK — fix with `flow:to_server,established;` + `content:"whitepepper.su"` (see `lumma_improved.rules`)
- Rule 1000004: `content:"POST"` matches any POST on port 80 — scope with host content check

---

## How I Did the Analysis

1. **Identify the victim** — DHCP, NBNS, Kerberos, and SAMR cross-checked
2. **Trace DNS activity** — isolate `whitepepper.su`, rule out DGA (no failed lookups)
3. **Isolate HTTP traffic** — filter to C2 host, then POST requests only
4. **Decode exfiltration payloads** — export from Wireshark, decode with Python
5. **Map to MITRE ATT&CK** — only techniques with packet/payload evidence
6. **Write and test Snort rules** — one indicator per rule for meaningful alert counts
7. **Replay against PCAP** — validate config, replay, count alerts by SID

See also: [`traffic analysis using snort rules and snort/Project Title.txt`](traffic%20analysis%20using%20snort%20rules%20and%20snort/Project%20Title.txt) for the workflow diagram.

---

## Key Commands Used

```bash
# PCAP info
capinfos pcaps/2026-01-31-traffic-analysis-exercise.pcap

# Protocol hierarchy
tshark -r pcaps/2026-01-31-traffic-analysis-exercise.pcap -q -z io,phs

# DNS queries
tshark -r pcaps/2026-01-31-traffic-analysis-exercise.pcap \
  -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq

# C2 HTTP traffic
tshark -r pcaps/2026-01-31-traffic-analysis-exercise.pcap \
  -Y 'http.host contains "whitepepper.su"' -T fields -e ip.dst

# Victim identification
tshark -r pcaps/2026-01-31-traffic-analysis-exercise.pcap -Y dhcp -T fields -e dhcp.option.hostname
tshark -r pcaps/2026-01-31-traffic-analysis-exercise.pcap -Y kerberos -V | grep -Ei "CNameString|client name"
tshark -r pcaps/2026-01-31-traffic-analysis-exercise.pcap \
  -Y "samr.samr_UserInfo21.full_name" -T fields -e samr.samr_UserInfo21.full_name

# Snort validation & replay
sudo snort -c /etc/snort/snort.conf -T
sudo snort -r pcaps/2026-01-31-traffic-analysis-exercise.pcap \
  -c /etc/snort/snort.conf -A console -q 2>&1 | tee analysis/snort_alerts.txt

# Alert breakdown
grep -oE '\[1:100000[0-9]:[0-9]+\]' analysis/snort_alerts.txt | sort | uniq -c

# Decode payload (using included script)
python3 scripts/decode_payload.py set_agentChromeact=log* -o analysis/chrome_decoded.txt
python3 scripts/decode_payload.py set_agentEdgeact=log* -o analysis/edge_decoded.txt
```

---

## Evidence Index

All 33 screenshots are cataloged in [`docs/EVIDENCE_INDEX.md`](docs/EVIDENCE_INDEX.md).

| Folder | Screenshots | Focus |
|---|---|---|
| `Basic recon & DNSHTTP filtering/` | 13 | PCAP stats, DNS, HTTP, C2 confirmation |
| `Decode and exfiltration evidence/` | 4 | Payload decoding — Chrome & Edge |
| `snort rules/` | 6 | Rule validation, PCAP replay, alert counts |
| `SOC Incident Response Lumma Malware/` | 10 | Victim ID, HTTP export, IR evidence |

---

## Tools Used

| Tool | Purpose |
|---|---|
| **Wireshark** | Visual packet analysis, HTTP object export |
| **tshark** | Command-line filtering and field extraction |
| **tcpdump** | Quick packet capture verification |
| **strings** | Binary/string extraction from payloads |
| **Snort 2.9.15** | IDS rule validation and PCAP replay |
| **Python 3** | URL-decode and JSON-parse exfiltrated payloads |
| **Ubuntu 22.04** | Analysis environment |

---

*This project was completed as part of SOC analyst preparation. PCAP source: [malware-traffic-analysis.net](https://malware-traffic-analysis.net)*   L u m m a - S t e a l e r - T r a f f i c - A n a l y s i s - a n d - s n o r t - d e t e c t i o n 
 
 