# Suspicious Command Execution & Privilege Abuse Investigation (ELK)

---

##  Alert Information

| Field | Value |
|------|-------|
| Alert ID | SOC-20250720-0016 |
| Severity | High |
| Timestamp | Jul 20, 2025 – 05:13:15 |
| Hostname | winserv2019.some.corp |
| Account Used | Administrator |
| Trigger | Suspicious command-line usage (cmd.exe) |

---

##  Investigation Objective

Determine whether the suspicious **cmd.exe usage** indicates:
- Malicious command execution  
- Privilege escalation  
- Persistence establishment  
- Continued attacker activity following Administrator compromise  

---

# 🔎 Step 1 — Identify Commands Executed via CMD

## Query Used

```kql
@timestamp >= "2025-07-20T05:13:15" 
and process.parent.name:cmd.exe 
and user.name:Administrator
```

##  Fields Added

- process.command_line  
- process.name  
- process.parent.name  

---

##  Findings

- CMD executed multiple administrative commands  
- Commands included user creation and group modification  
- Activity executed under compromised Administrator session  

 **Assessment:** Evidence of attacker establishing persistence and escalating privileges  

---

# 🔎 Step 2 — Correlate with Security Event ID 4732 (Group Membership)

## Query Used

```kql
@timestamp >= "2025-07-20T05:13:15" 
and (winlog.event_id:4732 or process.parent.name:cmd.exe)
```

##  Fields Added

- winlog.event_id  
- winlog.task  
- message  
- process.command_line  

---

##  Findings

- Newly created account added to multiple privileged groups  
- Security Event 4732 confirmed group membership changes  
- Correlation between CMD execution and security logs validated attacker activity  

**Assessment:** Clear privilege escalation and persistence mechanism  

---

#  Step 3 — Investigate PowerShell Activity (Script Block Logging)

##  Query Used

```kql
@timestamp >= "2025-07-20T05:13:15" 
and event.module:powershell 
and event.code:4104
```

##  Field Added

- powershell.file.script_block_text  

---

##  Findings

- PowerShell commands executed:  
  - whoami  
  - whoami /priv  

 **Assessment:** Classic discovery commands used to enumerate privileges and confirm execution context  

---

# Step 4 — Investigate Compression Tool Usage (Rar.exe)

##  Query Used

```kql
process.name:"Rar.exe"
```

---

##  Findings

- Rar.exe executed by newly created account  
- Execution occurred after persistence and privilege escalation  
- Parent process chain aligned with attacker session  

 **Assessment:** Possible staging for data exfiltration or artifact packaging  

---

#  Investigation Verdict

✅ True Positive – Confirmed attacker post-exploitation activity  
✅ Persistence via new user account  
✅ Privilege escalation through group membership changes  
✅ Discovery activity using PowerShell  
✅ Potential data staging using Rar.exe  

---

#  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|------|-----------|----|
| Execution | Command Shell | T1059.003 |
| Persistence | Create Account | T1136 |
| Privilege Escalation | Account Manipulation | T1098 |
| Discovery | Account Discovery | T1087 |
| Discovery | Permission Groups Discovery | T1069 |
| Collection | Archive Collected Data | T1560 |
| Exfiltration | Data Staged | T1074 |

---

#  SOC Escalation Summary (L2 Ready)

Following successful Administrator compromise, the attacker executed CMD commands to create a backdoor account and add it to privileged groups. Subsequent PowerShell discovery commands confirmed privilege enumeration. Later execution of Rar.exe suggests potential staging of data for exfiltration. Full host compromise is confirmed.

---
#  Lessons Learned

- CMD-based account manipulation is a common persistence method  
- Correlation between Sysmon and Security logs is critical for validation  
- PowerShell script block logging provides valuable attacker visibility  
- Legitimate tools like Rar.exe can be abused for exfiltration staging  

---


#  Skills Demonstrated

- Sysmon process chain investigation  
- Windows Security log correlation  
- Privilege escalation detection  
- PowerShell logging analysis  
- Post-exploitation activity reconstruction  
- MITRE ATT&CK mapping  
- SOC escalation reporting  

---
