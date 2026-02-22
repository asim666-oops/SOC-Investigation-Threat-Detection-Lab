#  SOC Investigation — Attack Lifecycle Analysis (Splunk BOTS v1)

---

##  Overview
This project demonstrates a **SOC investigation using Splunk (BOTS v1 dataset)** following the **Cyber Kill Chain** to track attacker activity from reconnaissance to payload delivery.

###  Objectives
- Identify attacker infrastructure
- Detect intrusion attempts
- Extract IOCs
- Perform threat intelligence correlation
- Document attack timeline

---

##  Attack Lifecycle Summary

###  Reconnaissance
- **Scanning IP:** 40.80.148.42  
- **Tool:** Acunetix Scanner  
- Automated probing detected against web server.

###  Exploitation
- **Brute Force IP:** 23.22.63.114  
- **Successful Access:** 40.80.148.42  
- **Attempts:** 142 (1 success)

###  Installation
- **Malware Uploaded:** 3791.exe  
- Sysmon logs confirmed execution and hash extraction.

###  Action on Objective
- Website defacement observed  
- Malicious file modified web content

###  Weaponization
- **Domain:** prankglassinebracket.jumpingcrab.com  
- **Attacker Email:** Lillian.rose@po1s0n1vy.com  
- Masquerading infrastructure identified

###  Delivery
- **Secondary Payload:** MirandaTateScreensaver.scr.exe  
- **MD5:** c99131e0169171935c5ac32615ed6261  
- Indicates fallback delivery mechanism

---

##  MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|-------|-----------|----|
| Recon | Active Scanning | T1595 |
| Credential Access | Brute Force | T1110 |
| Initial Access | Valid Accounts | T1078 |
| Persistence | Ingress Tool Transfer | T1105 |
| Execution | User Execution | T1204 |
| Defense Evasion | Obfuscated Files | T1027 |
| C2 | Application Layer Protocol | T1071 |
| Impact | Defacement | T1491 |

---

##  Key IOCs
**IPs:** 40.80.148.42, 23.22.63.114  
**Domain:** prankglassinebracket.jumpingcrab.com  
**Email:** Lillian.rose@po1s0n1vy.com  
**Malware:** 3791.exe, MirandaTateScreensaver.scr.exe  
**Hash:** c99131e0169171935c5ac32615ed6261  

---

##  Lessons Learned
- Recon detection is critical for early defense
- Brute force monitoring prevents account compromise
- File upload monitoring detects persistence
- Threat intel pivoting exposes attacker infrastructure
- Multi-log correlation improves accuracy

---

##  Improvements
- Enable account lockout policies
- Deploy WAF & EDR
- Monitor file uploads
- Integrate threat intel into SIEM
- Block malicious IPs/domains
- Monitor outbound traffic for C2

---

##  Skills Demonstrated
SOC Investigation • Threat Hunting • Splunk Analysis • OSINT Pivoting • MITRE Mapping • Incident Reporting

---

