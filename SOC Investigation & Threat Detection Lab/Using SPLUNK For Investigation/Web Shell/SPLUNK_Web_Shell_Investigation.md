#  Web Shell Incident Investigation Report

##  Alert Information

| Field | Value |
|--------|--------|
| Alert Name | Potential Web Shell Upload Detected |
| Alert Time | 14/09/2025 09:31:51 AM |
| Affected Resource | http://web.trywinme.thm |
| Log Source | web-alert |
| Suspicious IP | 171.251.232.40 |
| Web Application | WordPress |
| Severity | Critical |

---

# Executive Summary

On 14 September 2025, a security alert triggered for a potential web shell upload on the organization's public web server hosting a WordPress application.

Investigation revealed that the suspicious IP address **171.251.232.40** conducted:

1. A brute-force attack using Hydra against `wp-login.php`
2. Successful authentication attempts
3. Interaction with WordPress Theme Editor
4. Execution of a known web shell file named `b374k.php`
5. Multiple successful POST requests indicating command execution

Threat Intelligence review confirmed the IP address has been flagged as malicious more than 3000 times on AbuseIPDB.

The attacker successfully deployed and interacted with a web shell, achieving remote code execution capability on the web server.

---

#  Threat Intelligence Enrichment

## Suspicious IP: 171.251.232.40

- Flagged as malicious more than 3000 times (AbuseIPDB)
- Associated with brute force and web exploitation campaigns
- High confidence malicious reputation

This enrichment supports the malicious nature of the activity observed in SIEM logs.

---

#  Investigation Methodology

All investigation was conducted in Splunk using the `web-alert` index.

---

## 1️⃣ Initial Log Review

### Query
```
index=web-alert 171.251.232.40
| table _time clientip uri_path useragent method status
| sort +_time
```

### Findings

- High volume of requests from single IP
- User-Agent identified as: `Mozilla/5.0 (Hydra)`
- Targeted endpoint: `/wp-login.php`
- Multiple failed login attempts followed by successful authentication

### Conclusion

Clear brute force attack attempt using Hydra against WordPress login.

---

## 2️⃣ Post-Authentication Activity (Excluding Hydra)

### Query
```
index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"
| table _time clientip useragent uri_path referer referer_domain method status
```

### Findings

- POST request to `admin-ajax.php`
- Referer:
  http://web.trywinme.thm/wp-admin/theme-editor.php?file=b374k.php&theme=blocksy

### Analysis

The WordPress Theme Editor should not reference arbitrary external PHP files.

The parameter:
file=b374k.php

is highly suspicious and strongly indicates web shell deployment or interaction.

---

## 3️⃣ Web Shell Log Analysis

### Query
```
index=web-alert 171.251.232.40 b374k.php
| table _time clientip useragent uri_path referer referer_domain method status
| sort +_time
```

### Findings

- Access to `b374k.php`
- 4 successful POST requests (HTTP 200)
- Activity occurred immediately after login brute force
- No evidence of filename obfuscation

### Conclusion

Attacker successfully interacted with the web shell.

The POST requests likely represent:
- Command execution
- File system interaction
- Persistence establishment
- Potential data exfiltration

---

# Web Shell Research

File identified: `b374k.php`

Open-source research confirms that:

- "b374k" is a widely known PHP web shell
- Provides:
  - File manager
  - Command execution
  - Database interaction
  - Reverse shell capability
  - Privilege escalation support

This confirms that the activity observed represents full remote command execution capability.

---

#  Attack Timeline

| Time (Chronological) | Activity |
|----------------------|----------|
| T1 | Hydra brute force attempts on wp-login.php |
| T2 | Successful login observed |
| T3 | Access to WordPress Theme Editor |
| T4 | Reference to b374k.php |
| T5 | POST requests to web shell |
| T6 | Confirmed web shell interaction |

---

#  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|------------|----|
| Initial Access | Brute Force | T1110 |
| Credential Access | Password Guessing | T1110.001 |
| Persistence | Web Shell | T1505.003 |
| Execution | Command Shell | T1059 |
| Defense Evasion | Web Shell Deployment | T1505.003 |

---

#  Impact Assessment

- Web server fully compromised
- Remote command execution achieved
- WordPress admin account compromised
- Possible data exfiltration
- Potential lateral movement risk
- Website defacement or malware hosting risk

This incident should be treated as a confirmed security breach.

---

#  Lessons Learned

- Brute force detection must trigger automatic IP blocking
- WordPress admin activity requires monitoring
- Theme Editor is high risk and should be disabled
- Web shell detection rules should exist proactively
- Threat Intelligence enrichment strengthens investigation accuracy

---

# SOC Analyst Notes

- Clear attack progression from brute force to web shell deployment
- Logs did not capture initial upload method
- Possible upload vectors:
  - WordPress Theme Editor
  - File upload plugin
  - Vulnerable plugin exploitation
---

#  Final Verdict

Confirmed Web Server Compromise.

Attack chain:
Hydra Brute Force → WordPress Login Access → Theme Editor Abuse → b374k Web Shell Deployment → Remote Command Execution

Severity: Critical  
Status: Confirmed Breach  

---



