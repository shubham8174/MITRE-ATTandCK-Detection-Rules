# 🎯 MITRE ATT&CK Detection Rules

![SIGMA](https://img.shields.io/badge/SIGMA-Rules-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)
![Chronicle](https://img.shields.io/badge/Chronicle-SIEM-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-Compatible-000000?style=for-the-badge&logo=splunk&logoColor=white)

> A library of production-ready SIGMA detection rules mapped to MITRE ATT&CK techniques — built from real SOC experience triaging 200+ daily alerts on Chronicle SIEM and tested against enterprise telemetry.

---

## 📌 Overview

Detection engineering is the backbone of an effective SOC. This repository contains hand-crafted SIGMA rules targeting the most impactful attacker techniques seen in enterprise environments. Each rule includes false positive context, severity classification, and remediation guidance — ready to deploy in Chronicle, Splunk, Microsoft Sentinel, or any SIGMA-compatible SIEM.

---

## 🛡️ Rules Included

| Rule | MITRE ID | Tactic | Severity |
|---|---|---|---|
| Suspicious PowerShell Execution | T1059.001 | Execution | HIGH |
| LSASS Memory Access (Credential Dumping) | T1003.001 | Credential Access | CRITICAL |
| Scheduled Task for Persistence | T1053.005 | Persistence | HIGH |
| Brute Force Login Detection | T1110 | Credential Access | HIGH |
| Lateral Movement via Remote Services | T1021 | Lateral Movement | MEDIUM |
| DNS Tunneling / C2 via DNS | T1071.004 | Command & Control | MEDIUM |

---

## 🚀 Deployment

### Convert to your SIEM format using sigmac or pySigma:

```bash
# Install pySigma
pip install pysigma

# Convert to Splunk SPL
sigma convert -t splunk detection_rules.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t sentinel detection_rules.yml

# Convert to Elastic (ECS)
sigma convert -t elasticsearch detection_rules.yml
```

### Deploy directly in Chronicle SIEM:
1. Open Chronicle → Detection Engine → Rules
2. Click **New Rule**
3. Paste the converted rule
4. Set alert severity and enable

---

## 📋 Rule Detail Breakdown

### 🔴 T1059.001 — Suspicious PowerShell
Detects encoded commands, download cradles, and execution policy bypass — the most common techniques used in fileless malware and post-exploitation frameworks like PowerShell Empire and Cobalt Strike.

**Key indicators:**
- `-EncodedCommand` or `-enc` flags
- `IEX` / `Invoke-Expression` in command line
- `DownloadString` / `WebClient` (download cradles)
- `-ExecutionPolicy Bypass` combined with `-nop -hidden`

---

### 🔴 T1003.001 — LSASS Credential Dumping
Detects memory access to lsass.exe with specific access masks used by Mimikatz, procdump, and similar tools. Filters out legitimate security software to reduce false positives.

**Key access masks:**
- `0x1010`, `0x1410`, `0x147a` (read + query process info)

---

### 🟠 T1053.005 — Scheduled Task Persistence
Detects `schtasks.exe /create` combined with suspicious executables (PowerShell, cmd, mshta) or suspicious paths (AppData, Temp, Public) — common for malware persistence mechanisms.

---

### 🟠 T1110 — Brute Force
Aggregates Windows Event ID 4625 (failed logon) and 4771 (Kerberos pre-auth failure) — fires when a single source IP generates 20+ failures within 5 minutes.

---

### 🟡 T1021 — Lateral Movement
Monitors for NTLM-authenticated remote interactive (RDP) and network logons between internal hosts — especially valuable for detecting Pass-the-Hash and Pass-the-Ticket attacks.

---

### 🟡 T1071.004 — DNS Tunneling
Uses regex to identify DGA-like subdomains (high entropy, 30+ characters) that indicate C2 communication or data exfiltration over DNS.

---

## 🗺️ MITRE ATT&CK Navigator Coverage

```
Initial Access    │ Execution      │ Persistence    │ Privilege Esc
──────────────────┼────────────────┼────────────────┼──────────────
                  │ T1059.001 ✅  │ T1053.005 ✅  │
                  
Credential Access │ Defense Evasion│ Lateral Move   │ C2
──────────────────┼────────────────┼────────────────┼──────────────
T1003.001 ✅     │                │ T1021 ✅      │ T1071.004 ✅
T1110 ✅         │                │               │
```

---

## 📁 Project Structure

```
MITRE-ATTandCK-Detection-Rules/
│
├── detection_rules.yml          # All SIGMA rules
├── rules/                       # Individual rule files
│   ├── T1059_powershell.yml
│   ├── T1003_lsass_dump.yml
│   ├── T1053_scheduled_task.yml
│   ├── T1110_brute_force.yml
│   ├── T1021_lateral_movement.yml
│   └── T1071_dns_tunneling.yml
├── tests/                       # Test cases and sample logs
└── README.md
```

---

## 🔮 Roadmap

- [ ] Expand to 20+ SIGMA rules (full ATT&CK coverage)
- [ ] Add KQL versions for Microsoft Sentinel
- [ ] Add Chronicle YARA-L versions
- [ ] Build ATT&CK Navigator layer file
- [ ] Add unit tests with sample log data

---

## 🤝 Contributing

Detection rules improve with community input. If you have:
- False positive feedback from production deployments
- Additional detection ideas for existing techniques
- New technique coverage suggestions

Open an issue or submit a pull request!

---

## 👤 Author

**Shubham Singh**
MSc Cyber Security — University of Southampton 🇬🇧
Information Security Analyst | Detection Engineering | Chronicle SIEM

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/shubham-singh99/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/shubham8174)\


