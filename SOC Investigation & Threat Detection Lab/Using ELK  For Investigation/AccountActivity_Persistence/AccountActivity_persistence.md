# - Suspicious Administrator Activity Investigation (ELK)

---

##  Alert 1 — Administrator Logon Outside Business Hours

| Field | Value |
|------|-------|
| Alert ID | SOC-20250720-0014 |
| Severity | High |
| Timestamp | Jul 20, 2025 – 05:11:22 |
| Hostname | winserv2019.some.corp |
| Account | Administrator |
| Trigger | Administrator authentication outside business hours |

---

##  Investigation Objective

Determine whether the **Administrator logon** represents:
- Legitimate activity  
- Attacker post-exploitation access  
- Privilege abuse following ProxyLogon web shell compromise  

---

#  Step 1 — Confirm Administrator Logon (Windows Event ID 4624)

##  Query Used (KQL)

```kql
@timestamp >= "2025-07-20T05:11:22" 
and winlog.event_id:4624 
and host.name:winserv2019.some.corp 
and winlog.event_data.TargetUserName:Administrator
```

## Fields Added to Table

- winlog.event_id  
- host.name  
- winlog.event_data.TargetUserName  
- winlog.logon.type  
- winlog.event_data.IpAddress  

---

##  Findings

- Successful Administrator logon confirmed  
- Logon occurred at alert timestamp  
- Source IP: **203.0.113.55** (same as ProxyLogon attacker)  
- Logon Type indicated remote access (RDP / network logon)

 **Assessment:** Strong evidence of attacker leveraging compromised credentials

---

#  Step 2 — Correlate with Sysmon Process Creation (Event ID 1)

##  Query Used

```kql
@timestamp >= "2025-07-20T05:11:22" 
and winlog.event_id:1 
and user.name:Administrator
```

## Fields Added

- user.name  
- process.parent.name  
- process.command_line  

---

##  Findings

- Administrator initiated process chain after logon  
- Parent process aligned with Windows session initialization  
- No immediate malicious process observed in first execution chain  

 **Assessment:** Confirms successful interactive session established

---

#  Alert 2 — New User Account Creation

| Field | Value |
|------|-------|
| Alert ID | SOC-20250720-0015 |
| Severity | Critical |
| Timestamp | Jul 20, 2025 – 05:13:09 |
| Hostname | winserv2019.some.corp |
| Account Used | Administrator |
| Trigger | User Account Management: New user created |

---

#  Step 3 — Investigate Account Creation Activity

## Query Used

```kql
@timestamp >= "2025-07-20T05:13:10.000" 
and winlog.channel:Security 
and winlog.task:"User Account Management"
```

##  Fields Added

- winlog.event_id  
- winlog.task  
- message  

---

##  Findings

- User account creation event identified  
- Event initiated by Administrator account  
- Activity occurred shortly after suspicious logon  
- Message field confirmed new user creation action  

 **Assessment:** Strong persistence indicator following privilege compromise  

---

#  Attack Timeline Reconstruction

| Time | Activity |
|------|----------|
| 04:38 | ProxyLogon exploitation attempt |
| 04:45 | Web shell command execution |
| 05:11 | Administrator remote logon from attacker IP |
| 05:13 | New user account created (persistence) |

---

#  Investigation Verdict

✅ True Positive – Confirmed attacker activity  
✅ Administrator account compromised and abused  
✅ Successful remote authentication from attacker IP  
✅ Persistence established via new user creation  

---

#  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|------|-----------|----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Create Account | T1136 |
| Privilege Escalation | Valid Accounts | T1078 |
| Lateral Movement | Remote Services (RDP) | T1021 |
| Execution | Windows Session Initialization | T1059 |

---

#  SOC Escalation Summary (L2 Ready)

Following ProxyLogon exploitation and web shell activity, the attacker authenticated remotely using the Administrator account from IP **203.0.113.55**. Shortly after logon, the attacker created a new user account, indicating persistence establishment and continued host compromise.

Immediate containment and credential reset are recommended.

---
#  Lessons Learned

- Web shell exploitation often leads to credential abuse  
- Administrator activity outside business hours is a strong detection signal  
- Correlation between network + host logs reveals full compromise  
- Account creation events are high-confidence persistence indicators  

---

#  Skills Demonstrated

- ELK host-based investigation  
- Windows Security log analysis  
- Sysmon process correlation  
- Persistence detection  
- Attack timeline reconstruction  
- MITRE ATT&CK mapping  
- SOC escalation reporting  

---
