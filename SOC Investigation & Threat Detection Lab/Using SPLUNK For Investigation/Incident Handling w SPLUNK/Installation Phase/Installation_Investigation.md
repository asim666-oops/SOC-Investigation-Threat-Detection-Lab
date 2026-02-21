#  Installation Phase Investigation – Malware Deployment on `imreallynotbatman.com`

---

##  Phase Objective

After successful exploitation and admin login compromise, attackers typically deploy:

- Backdoors
- Web shells
- Malware payloads
- Persistence mechanisms

This phase investigates whether any malicious payload was uploaded and executed on the compromised webserver **192.168.250.70**.

---
##  Step 1 — Identify Executable Upload Attempts

**Search Query**
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```

**Purpose**
- Detect HTTP uploads containing executable files
- Identify potential malware payload delivery

---

##  Step 2 — Inspect Uploaded File Names

During analysis, the field `part_filename{}` revealed two uploaded files:

- **3791.exe** → Suspicious executable
- **agent.php** → Possible web shell

To confirm upload origin:

**Search Query**
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"
```

**Finding**
- File uploaded from attacker infrastructure (confirmed via client IP field)

---

##  Step 3 — Confirm File Presence Across Log Sources

To determine whether the uploaded file appeared in host logs:

**Search Query**
```
index=botsv1 "3791.exe"
```

**Host-Centric Log Sources Identified**
- Sysmon
- WinEventLog
- Fortigate UTM

---

##  Step 4 — Confirm Malware Execution via Sysmon

Sysmon **EventCode=1** represents process creation.

**Search Query**
```
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
```

**Conclusion**
- The executable **3791.exe** was successfully executed on the compromised host
- Confirms transition from exploitation → installation phase

---

## Investigation Findings

| Artifact | Observation |
|---------|-------------|
| Uploaded Executable | 3791.exe |
| Additional Payload | agent.php |
| Execution Evidence | Sysmon EventCode=1 |
| Executing User | NT AUTHORITY\IUSR |
| MD5 Hash | AAE3F5A29935E6ABCC2C2754D12A9AF0 |
| Malware Alias | ab.exe (Malicious) |

---
## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | User Execution / Malicious File | T1204 |
| Persistence | Web Shell | T1505.003 |
| Defense Evasion | Masquerading | T1036 |
| Command & Control | Ingress Tool Transfer | T1105 |
| Execution | Process Creation | T1059 |

---

##  Lessons Learned

- Successful brute-force attacks often lead to payload uploads
- File upload monitoring is critical for detecting malware staging
- Sysmon EventCode=1 provides reliable execution evidence
- Service accounts (IUSR) can be abused for malware execution
- Hash intelligence enrichment helps confirm malicious artifacts

---

## Detection & Prevention Improvements

- Restrict executable uploads via web server filtering
- Monitor multipart HTTP uploads containing binaries
- Deploy EDR rules for suspicious process creation by service accounts
- Implement application allowlisting on servers
- Automate hash reputation checks with threat intelligence feeds

---