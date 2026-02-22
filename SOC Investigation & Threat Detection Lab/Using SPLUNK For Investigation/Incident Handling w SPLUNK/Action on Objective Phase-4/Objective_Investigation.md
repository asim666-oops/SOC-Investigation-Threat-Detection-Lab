# Action on Objective – Website Defacement Investigation (`imreallynotbatman.com`)

---

##  Phase Objective

After gaining access and installing malware, the attacker achieved their final objective — **website defacement**.

This phase investigates:
- Outbound communication from compromised server
- External attacker infrastructure
- Defacement artifact delivery
- Evidence of attacker impact

---

##  Step 1 — Analyze Suricata Logs (Inbound Traffic)

**Search Query**
```
index=botsv1 dest=192.168.250.70 sourcetype=suricata
```

**Observation**
- No meaningful external inbound traffic linked to defacement
- Indicates attacker activity may involve outbound communication

---

##  Step 2 — Investigate Outbound Traffic from Web Server

**Search Query**
```
index=botsv1 src=192.168.250.70 sourcetype=suricata
```

**Key Insight**
- Web servers typically receive traffic, not initiate it
- Multiple outbound connections observed to external IPs
- Strong indicator of post-compromise communication

---

##  Step 3 — Pivot into Suspicious Destination IP

**Search Query**
```
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
```

**Findings**
- Communication with attacker-controlled host
- URL field revealed:
  - Two PHP files
  - One suspicious JPEG file

---

##  Step 4 — Identify Defacement Artifact Source

**Search Query**
```
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70"
| table _time src dest_ip http.hostname url
```

**Conclusion**
- Defacement image downloaded from attacker infrastructure
- Malicious host:
```
prankglassinebracket.jumpingcrab.com
```

---

##  Investigation Findings

| Artifact | Observation |
|---------|-------------|
| Defacement File | poisonivy-is-coming-for-you-batman.jpeg |
| Download Source | prankglassinebracket.jumpingcrab.com |
| Communication Direction | Outbound from compromised server |
| Destination IP | 23.22.63.114 |
| Impact | Website visual defacement |

---

##  Firewall Detection Evidence

Fortigate Firewall logs confirmed SQL injection activity.

| Detection Source | Rule Triggered |
|------------------|----------------|
| Fortigate UTM | HTTP.URI.SQL.Injection |
| Attacker IP | 40.80.148.42 |

---
##  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Command & Control | Application Layer Protocol | T1071 |
| Exfiltration | Exfiltration Over Web Services | T1567 |
| Impact | Defacement | T1491 |
| Impact | Data Manipulation | T1565 |
| Persistence | Web Shell | T1505.003 |

---

##  Lessons Learned

- Outbound traffic from servers can indicate compromise
- Defacement artifacts may be hosted externally and downloaded post-exploitation
- Network pivoting helps reveal attacker infrastructure
- Firewall detections provide valuable corroboration of web attacks
- Correlating Suricata + Web + Firewall logs reveals attacker objectives

---

##  Detection & Prevention Improvements

- Monitor abnormal outbound server communication
- Implement file integrity monitoring for web content
- Restrict outbound traffic from production servers
- Deploy WAF to block SQL injection attempts
- Alert on suspicious media downloads by web servers
- Harden CMS and plugin security

---