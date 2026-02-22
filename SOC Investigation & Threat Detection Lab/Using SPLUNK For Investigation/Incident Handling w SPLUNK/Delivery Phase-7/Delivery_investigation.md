#  Delivery Phase — Malware Discovery & Final Findings

---

##  Phase Objective

The **Delivery phase** focuses on how attackers deliver malicious payloads into the victim environment. Adversaries may use:

• Malware hosted on attacker infrastructure  
• Phishing attachments or malicious downloads  
• Secondary payloads for persistence  
• Staged delivery through compromised servers  

Threat intelligence indicated that the attacker maintained a **secondary delivery mechanism** in case the initial compromise attempt failed.

---

##  Known Attacker Infrastructure

| Type | Value |
|------|------|
| Attacker IP | 23.22.63.114 |
| Suspected Adversary Theme | Poison Ivy themed infrastructure |

---

## Step 1 — ThreatMiner Investigation

**Tool:** ThreatMiner  
**Purpose:** Identify malware samples associated with attacker infrastructure

###  Findings
ThreatMiner revealed **three malware samples** associated with the attacker IP.  
One suspicious file stood out as malicious:

| Hash Type | Value |
|----------|------|
| MD5 | c99131e0169171935c5ac32615ed6261 |

This sample was selected for deeper intelligence analysis.

---

##  Step 2 — VirusTotal Intelligence Analysis

**Tool:** VirusTotal  

###  Purpose
• Confirm malicious classification  
• Extract file metadata and indicators  
• Identify detection coverage across AV engines  

###  Key Insights
• Malware flagged by multiple security engines  
• Metadata confirmed malicious intent  
• Indicators linked back to attacker infrastructure  
• Evidence of staged payload delivery

---

##  Step 3 — Hybrid Analysis Behavioral Investigation

**Tool:** Hybrid Analysis  

###  Purpose
• Observe runtime malware behavior  
• Extract network and system artifacts  
• Map adversary activity to MITRE ATT&CK  

###  Behavioral Artifacts Observed

• Malicious outbound network communication  
• DNS queries to attacker-controlled domains  
• Contact with command & control infrastructure  
• Suspicious file system modifications  
• Possible persistence mechanisms  
• Extracted configuration strings  
• Mutex creation indicators  
• Execution screenshots and runtime traces  

---

##  Final Confirmed Malware

Further intelligence correlation confirmed the malware used as a **secondary delivery payload**.

| Artifact | Value |
|---------|------|
| Malware Name | MirandaTateScreensaver.scr.exe |
| MD5 | c99131e0169171935c5ac32615ed6261 |
| Role | Secondary staged payload |
| Delivery Method | Hosted on attacker infrastructure |
| Behavior | Likely user-executed to initiate persistence and C2 |

---

##  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|-------|-----------|----|
| Resource Development | Stage Capabilities | T1587 |
| Initial Access | User Execution | T1204 |
| Execution | Malicious File Execution | T1204.002 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Command & Control | Application Layer Protocol | T1071 |
| Command & Control | Web Service | T1102 |

---

##  Lessons Learned

• Pivoting from attacker infrastructure reveals hidden payloads  
• Secondary delivery mechanisms indicate advanced adversary planning  
• Behavioral sandboxing provides deeper insight than static analysis  
• Threat intelligence correlation improves investigation confidence  
• Hash intelligence enables proactive threat detection  

---

##  Detection & Prevention Improvements

• Integrate threat intelligence feeds into SIEM for automated enrichment  
• Block attacker infrastructure identified during OSINT pivoting  
• Deploy sandbox detonation for suspicious files and attachments  
• Implement hash-based detection across endpoints and EDR  
• Monitor outbound connections to suspicious IP infrastructure  
• Apply email filtering controls to block executable payload delivery  
• Conduct user awareness training against suspicious file execution  

---