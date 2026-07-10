# SOC Incident Response Report

## Lumma Stealer traffic analysis and snort detection

| Field | Value |
|---|---|
| **Analyst** | Gaurab Dahal |
| **Date** | july 2026 |
| **Malware** | Lumma Stealer 
| **Source** | [malware-traffic-analysis.net](https://malware-traffic-analysis.net) |
| **Tools Used** | Wireshark, tshark, tcpdump, strings, Snort 2.9.15, Python 3, Ubuntu 22.04 |
| **Result** | Detection Confirmed — 59 Snort alerts generated |

> **Note:** The raw PCAP is not included in this repository. Machine-readable IOCs are in [`../data/`](../data/). Snort rules are in [`../rules/`](../rules/).

---

## 1. Executive Summary

A Windows 11 machine on the `WIN11OFFICE` network was infected with Lumma Stealer — a commodity infostealer rented on cybercrime forums as a subscription service. Once active, the malware communicated over plain HTTP to `whitepepper.su` (`153.92.1.49`), a C2 server using the `.su` (Soviet Union) TLD, which is cheap and lightly regulated.

Two fingerprint uploads occurred **7 seconds apart**: Chrome (8,023 bytes) then Edge (7,975 bytes). That interval is too fast for manual browser switching — consistent with automated collection across installed browsers.

This Lumma build did not use HTTPS, so exfiltration payloads were visible in cleartext. Decoded data showed browser/hardware fingerprints and anti-sandbox checks (`webdriver:false`, 12-core CPU validation), not stolen passwords in the network capture.

**Key outcomes:** one infected host, one confirmed C2 domain, two exfiltration events, eight MITRE ATT&CK techniques with packet evidence, four Snort rules validated, **59 alerts** on PCAP replay.

---

## 2. Victim Identification

Four independent protocols corroborate the victim identity:

| Field | Value | Found Via | Command / Filter |
|---|---|---|---|
| IP Address | 10.1.21.58 | DHCP / HTTP | `tshark -z endpoints,ip` |
| MAC Address | 00:04:c1:be:8c:d4 | Ethernet / DHCP | `tshark -T fields -e eth.src` |
| Hostname | DESKTOP-ES9F3ML | DHCP Option 12 | `tshark -Y dhcp -e dhcp.option.hostname` |
| Username | gwyatt | Kerberos AS-REQ | `tshark -Y kerberos.CNameString` |
| Full Name | Gabriel Wyatt | SAMR QueryUserInfo | `samr.samr_UserInfo21.full_name` |
| Domain | WIN11OFFICE | Kerberos | `kerberos && ip.src==10.1.21.58` |
| Operating System | Windows NT 10.0 x64 | HTTP User-Agent | `http.user_agent` |
| Last Logon | Jan 28, 2026 | SAMR | Wireshark SAMR dissection |

**Evidence:** [`../SOC Incident Response Lumma Malware/`](../SOC%20Incident%20Response%20Lumma%20Malware/)

---

## 3. Command and Control Infrastructure

| IOC Type | Value | Notes |
|---|---|---|
| C2 Domain | whitepepper.su | `.su` TLD — common in Eastern European malware infrastructure |
| C2 IP | 153.92.1.49 | Confirmed via DNS and HTTP destination |
| C2 URI | /api/set_agent | Bot check-in and data upload path |
| Bot ID | 3BF67EC05320C5729578BE4C0ADF174C | Victim tag sent on every beacon |
| Auth Token | 842e2802df0f0a06b4ed51f12f4387e761523b | C2 panel authentication |
| Protocol | Plain HTTP, port 80 | No encryption — payloads readable in Wireshark |

**Evidence:** [`../Basic recon & DNSHTTP filtering/08_c2_ip_confirmed.png`](../Basic%20recon%20%26%20DNSHTTP%20filtering/08_c2_ip_confirmed.png)

---

## 4. Attack Timeline

All timestamps from PCAP replay through Snort.

| Time (UTC) | Event | Evidence | MITRE Tactic |
|---|---|---|---|
| 04:50:38.454 | TCP connections to 153.92.1.49 | Snort SID 1000001 (×6) | TA0011 Command & Control |
| 04:50:39.253 | GET /api/set_agent — Chrome beacon | SID 1000002 + 1000003 | TA0011 Command & Control |
| 04:50:40.196 | POST — Chrome exfil (8,023 B) | SID 1000004 | TA0010 Exfiltration |
| 04:50:47.099 | GET /api/set_agent — Edge beacon | SID 1000002 + 1000003 | TA0011 Command & Control |
| 04:50:47.462 | POST — Edge exfil (7,975 B) | SID 1000004 | TA0010 Exfiltration |
| 04:50:51.058 | Session closes | SID 1000001 | TA0011 Command & Control |

---

## 5. Analysis Methodology

### Step 1 — Identify the host

| Protocol | Filter | Result |
|---|---|---|
| DHCP | `dhcp` | DESKTOP-ES9F3ML |
| NBNS | `nbns` | Confirms DHCP hostname |
| Kerberos | `kerberos.CNameString` | gwyatt / WIN11OFFICE |
| SAMR | `samr` | Gabriel Wyatt |
| LDAP | `ldap && ip.src==10.1.21.58` | None found |

### Step 2 — Trace DNS

| Purpose | Filter | Result |
|---|---|---|
| Outbound lookups | `dns.flags.response == 0` | All queried domains |
| C2 resolution | `dns.resp.name == "whitepepper.su"` | 153.92.1.49 |
| Failed lookups | `dns.flags.rcode == 3` | None — no DGA behavior |

### Step 3 — Isolate HTTP traffic

| Purpose | Filter |
|---|---|
| C2 only | `http.host == "whitepepper.su"` |
| Exfiltration only | `http.host=="whitepepper.su" && http.request.method=="POST"` |
| Large uploads | `http.request.method=="POST" && http.content_length>1000` |

**Evidence:** [`../Basic recon & DNSHTTP filtering/`](../Basic%20recon%20%26%20DNSHTTP%20filtering/)

---

## 6. Payload Decoding

POST bodies were exported from Wireshark (File → Export Objects → HTTP) and decoded with [`../scripts/decode_payload.py`](../scripts/decode_payload.py).

```bash
python3 scripts/decode_payload.py set_agentChromeact=log* -o analysis/chrome_decoded.txt
python3 scripts/decode_payload.py set_agentEdgeact=log* -o analysis/edge_decoded.txt
```

### Decoded fields (Chrome vs Edge)

| Field | Chrome | Edge | MITRE |
|---|---|---|---|
| Timestamp | 2026-01-27T23:05:40.634Z | 2026-01-27T23:05:48.457Z | T1119 |
| GPU | AMD Radeon R9 200 | Microsoft Basic Render Driver | T1497.001 |
| WebDriver | false | false | T1497.001 |
| CPU Cores | 12 | 12 | T1497.001 |
| Screen | 1920×1080, 24-bit | 1920×1080, 24-bit | T1082 |
| Upload Size | 8,023 bytes | 7,975 bytes | T1041 |

**Important:** These payloads are **browser/device fingerprints**, not credential dumps. Credential theft from `Login Data` SQLite files occurs locally and would not appear in this network capture.

**Evidence:** [`../Decode and exfiltration evidence/`](../Decode%20and%20exfiltration%20evidence/)

---

## 7. MITRE ATT&CK Mapping

Only techniques with direct packet/payload evidence are claimed.

| Tactic | ID | Technique | Evidence |
|---|---|---|---|
| Command & Control | T1071.001 | Application Layer Protocol: Web | HTTP GET to whitepepper.su/api/set_agent |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | POST packets 24601 (8,023 B) and 25286 (7,975 B) |
| Credential Access | T1555.003 | Credentials from Web Browsers | Chrome + Edge profiles targeted |
| Discovery | T1082 | System Information Discovery | GPU, CPU, screen, OS in payload |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion | webdriver:false + 12-core check |
| Collection | T1119 | Automated Collection | Chrome → Edge in 7 seconds |
| Discovery | T1016 | System Network Configuration Discovery | Network type/speed in payload |
| Discovery | T1033 | System Owner/User Discovery | Bot ID tags victim across sessions |

**Not claimed** (no evidence in this capture): Initial Access, Execution, Persistence, Lateral Movement.

---

## 8. Snort IDS Rules

Rules are stored in [`../rules/lumma.rules`](../rules/lumma.rules) (original) and [`../rules/lumma_improved.rules`](../rules/lumma_improved.rules) (reduced false positives).

### Validation workflow

```bash
# 1. Validate config
sudo snort -c /etc/snort/snort.conf -T

# 2. Replay PCAP and save alerts
sudo snort -r pcaps/2026-01-31-traffic-analysis-exercise.pcap \
  -c /etc/snort/snort.conf -A console -q 2>&1 | tee analysis/snort_alerts.txt

# 3. Count alerts
wc -l analysis/snort_alerts.txt
grep -oE '\[1:100000[0-9]:[0-9]+\]' analysis/snort_alerts.txt | sort | uniq -c
```

**Evidence:** [`../snort rules/`](../snort%20rules/)

---

## 9. Detection Results

| SID | Rule Name | Alerts | Assessment |
|---|---|---|---|
| 1000001 | Lumma C2 IP | 45 | Noisy — fires on TCP handshakes |
| 1000002 | Lumma Domain | 6 | Clean |
| 1000003 | Lumma URI | 6 | Clean |
| 1000004 | Lumma POST | **2** | Precise — Chrome + Edge exfil |
| | **TOTAL** | **59** | **Confirmed** |

Sample alert:
```
01/28-04:50:40.196368 [**] [1:1000004:1] Lumma POST [**] {TCP} 10.1.21.58:54492 -> 153.92.1.49:80
```

Machine-readable results: [`../data/detection_results.csv`](../data/detection_results.csv)

---

## 10. Known Weaknesses and Fixes

| Rule | Problem | Fix |
|---|---|---|
| 1000001 | Fires on every SYN/ACK — 45 alerts for ~6 events | Add `flow:to_server,established;` + `content:"whitepepper.su"` |
| 1000004 | `content:"POST"` matches any POST on port 80 | Scope with `content:"whitepepper.su"` in same rule |

Improved rules are in [`../rules/lumma_improved.rules`](../rules/lumma_improved.rules).

---

## 11. Complete IOC Table

Export-ready IOCs: [`../data/iocs.csv`](../data/iocs.csv) and [`../data/iocs.json`](../data/iocs.json)

| Type | Value |
|---|---|
| Victim IP | 10.1.21.58 |
| Victim MAC | 00:04:c1:be:8c:d4 |
| Hostname | DESKTOP-ES9F3ML |
| Username | gwyatt |
| Full Name | Gabriel Wyatt |
| Domain | WIN11OFFICE |
| C2 Domain | whitepepper.su |
| C2 IP | 153.92.1.49 |
| C2 URI | /api/set_agent |
| Bot ID | 3BF67EC05320C5729578BE4C0ADF174C |
| Auth Token | 842e2802df0f0a06b4ed51f12f4387e761523b |
| Malware Family | Lumma Stealer |

---

## 12. Recommendations

1. **Block IOCs** at firewall/proxy: `whitepepper.su`, `153.92.1.49`
2. **Deploy improved Snort rules** from `rules/lumma_improved.rules`
3. **Isolate** host `DESKTOP-ES9F3ML` (10.1.21.58) and image for forensic analysis
4. **Reset credentials** for user `gwyatt` — local credential theft may have occurred off-wire
5. **Hunt** for Lumma persistence and additional C2 channels not visible in this capture

---

*Report prepared as part of SOC analyst portfolio work. PCAP source: malware-traffic-analysis.net*
