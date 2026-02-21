#  Web Shell Activity Investigation Report (ELK)

---

##  Alert Information

| Field | Value |
|-------|--------|
| Alert ID | SOC-20250720-0012 |
| Severity | High |
| Timestamp | Jul 20, 2025 – 04:38:40 |
| Client IP | 203.0.113.55 |
| Destination Host | winserv2019.some.corp |
| Trigger | Multiple POST requests to proxyLogon.ecp |

---

##  Investigation Objective

Determine whether web requests from **203.0.113.55** indicate exploitation of Exchange ProxyLogon and potential web shell deployment.

---

#  Step 1 — Initial Alert Triage

## Observation

- High severity alert triggered  
- POST requests observed to **proxyLogon.ecp**  
- Known exploitation path for Microsoft Exchange ProxyLogon  

 **Hypothesis:** Possible automated exploitation attempt  

---

#  Step 2 — Visualizing POST Requests in Kibana

##  Query Used

```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST
```

##  Table Columns Added

- client.ip  
- user.agent  
- http.request.method  
- url.path  
- http.response.status_code  

##  Findings

- Multiple POST requests to ProxyLogon endpoint  
- Repetitive request pattern indicating automation  
- Suspicious user-agent string observed  

 **Assessment:** Strong indicator of exploitation attempt  

---

#  Step 3 — Correlated High-Severity Alert

| Field | Value |
|-------|--------|
| Alert ID | SOC-20250720-0013 |
| Severity | High |
| Timestamp | Jul 20, 2025 – 04:45:31 |
| Client IP | 203.0.113.55 |
| Trigger | Multiple GET requests to errorEE.aspx with cmd parameter |

## Observation

- Alert triggered 7 minutes after exploitation attempt  
- Presence of **cmd=** parameter → web shell behavior indicator  

 **Hypothesis:** Attacker successfully deployed a web shell  

---

# 🔎 Step 4 — Web Shell Investigation in Kibana

## Query Used

```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:GET and errorEE.aspx
```

## Investigation Actions

- Sorted events Old → New  
- Reviewed url.path for command execution patterns  

---

# Step 5 — Evidence of Command Execution

## Indicators Observed

- GET requests containing **cmd=** parameter  
- Commands embedded directly in URL path  
- Sequential execution pattern  

 **Conclusion:** Confirmed web shell activity  

---

#  Attack Chain Reconstruction

1️⃣ ProxyLogon exploitation attempt (POST proxyLogon.ecp)  
2️⃣ Authentication bypass / file upload likely occurred  
3️⃣ Web shell deployment (errorEE.aspx)  
4️⃣ Command execution via cmd parameter  
5️⃣ Post-exploitation remote access achieved  

---

#  Investigation Verdict

| Alert ID | Verdict | Reason |
|----------|--------|--------|
| SOC-20250720-0012 | True Positive | ProxyLogon exploitation attempt |
| SOC-20250720-0013 | True Positive | Confirmed web shell command execution |

---

#  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|-------|-----------|----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Server Software Component: Web Shell | T1505.003 |
| Execution | Command Shell | T1059 |
| Command & Control | Web Protocols | T1071.001 |

---


#  Lessons Learned

- Public-facing Exchange servers remain high-value targets  
- Web server logs provide early exploitation visibility  
- Alert correlation is critical for full attack chain reconstruction  
- Automation patterns in logs are strong compromise indicators  

---

#  Detection Improvements

- Create detection rule for **cmd parameter in ASPX requests**  
- Detect anomalous POST requests to Exchange ECP paths  
- Alert on suspicious or automation-based user-agent strings  
- Correlate exploitation attempts with web shell execution alerts  

---

#  Skills Demonstrated

- ELK Stack investigation  
- Kibana KQL threat hunting  
- Web shell detection  
- Exchange exploitation analysis  
- Attack chain reconstruction  
- MITRE ATT&CK mapping  
- SOC escalation reporting  

---
