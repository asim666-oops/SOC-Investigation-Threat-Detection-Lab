#  Brute Force Investigation Using SPLUNK

##  Alert Information

| Field | Value |
|-------|--------|
| Alert Name | Brute Force Activity Detection |
| Index | linux-alert |
| Sourcetype | linux_secure |
| Target Host | tryhackme-2404 |
| Source IP | 10.10.242.248 |

---

##  Investigation Objective

To determine whether the detected login activity from source IP 10.10.242.248 was:

- A false positive  
- A brute force attempt  
- A successful compromise  
- Followed by privilege escalation  

---

#  Investigation Steps

---

## 🔹 Step 1: Identify Targeted Users on Host

### SPL Query

```spl
index="linux-alert" sourcetype="linux_secure" Hostname=tryhackme-2404
| stats count by user_name
```

###  Purpose

- Identify which users had login activity on the target host  
- Detect unusual login attempt volume  

---

## 🔹 Step 2: Review All Login Activity from Suspicious IP

### SPL Query

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
("Failed password" OR "Accepted password" OR "Invalid user") 
| sort -_time
```

###  Purpose

- Check for brute force patterns  
- Identify failed login attempts  
- Detect invalid user enumeration  
- Verify if successful login occurred  

---

## 🔹 Step 3: Detect Username Enumeration

### SPL Query

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
("Invalid user") 
| sort -_time
```

###  Purpose

- Identify login attempts using non-existent accounts  
- Confirm attacker reconnaissance behavior  

###  Finding

- Multiple "Invalid user" attempts observed  
- Indicates username enumeration phase  

---

## 🔹 Step 4: Focus on Targeted User (john.smith)

### SPL Query

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248 john.smith
("Failed" OR "Accepted")
| eval process="sshd"
| stats count by user_name, action, Hostname, src
```

###  Purpose

- Count login attempts for john.smith  
- Compare failed vs successful attempts  
- Confirm brute force activity  

###  Finding

- 500+ failed login attempts  
- One successful login detected  

Confirms successful brute force attack  

---

## 🔹 Step 5: Check for Privilege Escalation (sudo Activity)

### SPL Query

```spl
index="linux-alert" sourcetype="linux_secure"
john.smith sudo
```

###  Purpose

- Determine whether the compromised account executed sudo commands  
- Identify privilege escalation attempts  

###  Finding

- sudo activity detected  
- Indicates privilege escalation behavior  

---

## 🔹 Step 6: Check for Root-Level Activity

### SPL Query

```spl
index="linux-alert" sourcetype="linux_secure" root 
(*Adduser*)
```

###  Purpose

- Identify if attacker escalated privileges to root  
- Detect new user creation (persistence mechanism)  

###  Finding

- Root-level activity observed  
- Evidence of user creation detected  

---

#  Investigation Summary

| Attack Phase | Observation |
|--------------|------------|
| Enumeration | Multiple "Invalid user" attempts |
| Brute Force | 500+ failed login attempts |
| Compromise | Successful login to john.smith |
| Privilege Escalation | sudo activity observed |
| Persistence | Root activity and new user creation detected |

---

#  MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|--------------|----------------|------------|
| T1110 | Brute Force | Repeated password guessing attempts |
| T1589 | Gather Victim Identity Information | Username enumeration attempts |
| T1078 | Valid Accounts | Successful login using compromised credentials |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo | Privilege escalation via sudo |
| T1136 | Create Account | New user creation for persistence |
| T1059 | Command and Scripting Interpreter | Command execution after compromise |

---

#  Final Verdict

True Positive – Confirmed Brute Force Attack  
Successful compromise of john.smith account  
Privilege escalation to root  
Persistence mechanism established  

---

#  Lessons Learned

- Excessive failed login attempts are strong brute-force indicators  
- Username enumeration often precedes successful compromise  
- Monitoring sudo activity is critical after authentication events  
- Root-level actions should always trigger high-severity alerts  
- Persistence mechanisms (new user creation) must be audited immediately  

---

#  Improvements & Recommendations

###  Security Improvements

- Implement account lockout policies  
- Enforce strong password policies  
- Enable Multi-Factor Authentication (MFA)  
- Restrict SSH access to trusted IP ranges  
- Disable password-based SSH authentication (use key-based auth)

---

#  Skills Demonstrated

- Splunk SPL log analysis  
- Brute force detection  
- Threat hunting  
- Privilege escalation investigation  
- Persistence detection  
- MITRE ATT&CK mapping  
- SOC investigation workflow  

---
