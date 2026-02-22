#  Command & Control Phase – C2 Infrastructure Investigation (`imreallynotbatman.com`)

---

##  Phase Objective

During the post-exploitation stage, the attacker used **Dynamic DNS infrastructure** to communicate with their Command & Control (C2) server.

This phase focuses on:
- Identifying attacker C2 domain
- Correlating firewall, HTTP, and DNS logs
- Confirming communication between compromised server and adversary infrastructure

---

##  Step 1 — Investigate Firewall Logs (Fortigate)

**Search Query**
```
index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"
```

###  Purpose
- Identify firewall events associated with defacement artifact
- Extract domain (FQDN) contacted by compromised server
- Determine attacker infrastructure

###  Finding
- Firewall logs revealed destination FQDN
- Domain identified as attacker-controlled infrastructure

```
prankglassinebracket.jumpingcrab.com
```

---

##  Step 2 — Validate via HTTP Stream Logs

**Search Query**
```
index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70
```

###  Purpose
- Confirm HTTP communication between compromised server and attacker IP
- Validate artifact download source
- Strengthen evidence of C2 activity

###  Finding
- HTTP logs confirmed:
  - Source: Compromised web server (192.168.250.70)
  - Destination: Attacker IP (23.22.63.114)
  - Artifact retrieved from malicious domain

---

##  Investigation Findings

| Evidence | Observation |
|---------|-------------|
| C2 Domain | prankglassinebracket.jumpingcrab.com |
| Attacker IP | 23.22.63.114 |
| Communication Type | HTTP + DNS |
| Downloaded Artifact | poisonivy-is-coming-for-you-batman.jpeg |
| Infrastructure Type | Dynamic DNS |

---

## Final Verdict

✅ Confirmed Command & Control communication  
✅ Compromised server initiated outbound connection  
✅ Dynamic DNS used to mask attacker infrastructure  
✅ C2 server delivered defacement artifact  

---

##  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Command & Control | Application Layer Protocol | T1071 |
| Command & Control | Dynamic Resolution | T1568 |
| Command & Control | Web Protocols | T1071.001 |
| Defense Evasion | Domain Generation / Dynamic DNS | T1568.002 |

---

##  Lessons Learned

- Dynamic DNS is frequently used to hide attacker infrastructure
- Firewall logs provide early visibility into C2 communication
- DNS telemetry is critical for uncovering hidden attacker domains
- Correlating HTTP + Firewall + DNS logs strengthens investigation confidence
- Outbound traffic monitoring is essential for detecting compromised servers

---

##  Detection & Prevention Improvements

- Monitor DNS queries to Dynamic DNS providers
- Implement DNS filtering and sinkholing
- Restrict outbound traffic from production servers
- Alert on abnormal web requests originating from servers
- Deploy EDR + NDR correlation for C2 detection
- Use threat intelligence feeds to block known malicious domains

---