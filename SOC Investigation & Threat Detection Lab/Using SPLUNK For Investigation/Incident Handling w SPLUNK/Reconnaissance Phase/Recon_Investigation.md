#  Reconnaissance Phase Investigation – Web Server `imreallynotbatman.com`

---

##  Overview

Reconnaissance is the phase where an attacker attempts to gather information about a target, including:  

- System or web application details  
- Employees or organizational structure  
- Server configurations  

From a SOC perspective, the goal is to identify suspicious scanning activity against the webserver `imreallynotbatman.com`.

---

##  Step 1 — Initial Domain Search

**Search Query:**  
```
index=botsv1 imreallynotbatman.com
```

**Explanation:**  
- Search all logs in index `botsv1` containing our target domain  
- Time Range: **All Time**  
- Identified log sources containing traces of the domain:
  - Suricata
  - stream:http
  - fortigate_utm
  - iis

---

##  Step 2 — HTTP Traffic Analysis

**Search Query:**  
```
index="botsv1" imreallynotbatman.com sourcetype="stream:http"
```

**Alternative with top IPs:**  
```
index="botsv1" imreallynotbatman.com sourcetype="stream:http"
| top src_ip
```

**Findings:**  
- Two main source IPs observed in the logs:  
  1. `40.80.148.42` → High percentage of traffic → Suspicious  
  2. `23.22.63.114` → Low percentage → Less likely attacker

**Next Steps:**  
- Narrow search to the suspicious IP  
- Examine **User-Agent**, POST requests, and URI patterns  

---

##  Step 3 — Suricata Alert Correlation

**Search Query:**  
```
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
```

**Top Suricata Alerts Observed:**

| Alert | Count | % |
|-------|-------|---|
| ET WEB_SERVER Script tag in URI, Possible Cross Site Scripting Attempt | 103 | 21.776% |
| ET WEB_SERVER Onmouseover= in URI - Likely XSS Attempt | 48 | 10.148% |
| ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY | 41 | 8.668% |
| SURICATA HTTP Host header invalid | 35 | 7.4% |
| ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM | 33 | 6.977% |
| ET WEB_SERVER SQL Injection Select Sleep Time Delay | 32 | 6.765% |
| ET WEB_SERVER Possible CVE-2014-6271 Attempt | 18 | 3.805% |
| ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers | 18 | 3.805% |
| ET WEB_SERVER PHP tags in HTTP POST | 13 | 2.748% |
| GPL WEB_SERVER global.asa access | 12 | 2.537% |

**Observation:**  
- Attack activity includes **XSS**, **SQLi**, **XXE**, and known **CVE exploit attempts**

---

##  Step 4 — Detailed HTTP Traffic Table

**Search Query:**  
```
index="botsv1" imreallynotbatman.com sourcetype="stream:http" src_ip="40.80.148.42"
| table src_ip http_user_agent uri http_method
```

**Purpose:**  
- Examine User-Agent strings  
- Check accessed URIs  
- Validate HTTP methods used in reconnaissance  

---

##  Key Findings

1. **CVE associated with attack:**  
```
CVE-2014-6271
```

2. **CMS used by the web server:**  
```
Joomla
```

3. **Attacker’s scanning host:**  
```
192.168.250.70
```

---

##  Attack Phase Summary

- **Reconnaissance Target:** `imreallynotbatman.com`  
- **Suspicious Source IP:** `40.80.148.42`  
- **Attack Vector Identified:** CVE-2014-6271 (Shellshock)  
- **Other Observed Techniques:**
  - XSS probing
  - SQL Injection attempts
  - XXE payload attempts  
- **Web Server CMS:** Joomla  
- **Attacker Scanner Host:** 192.168.250.70

---

##  MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Reconnaissance | Search Open Websites/Domains | T1590.002 |
| Reconnaissance | Gather Victim Network Information | T1590.004 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter | T1059 |
| Defense Evasion | Exploitation for Defense Evasion | T1211 |

---

##  Lessons Learned

- Reconnaissance traffic often shows patterns in HTTP methods, URIs, and User-Agent strings  
- Known CVEs (like **CVE-2014-6271**) are frequently targeted in automated scans  
- Cross-checking multiple log sources (HTTP, Suricata, Firewall) increases confidence in detection  
- Reconnaissance can be an early indicator of potential compromise  

---

##  Detection Improvements

- Monitor for high-frequency requests from a single IP  
- Alert on known CVE attempts against public-facing services  
- Track unusual User-Agent strings for automated scanners  
- Correlate network logs with Suricata signatures for real-time SOC alerts  

---