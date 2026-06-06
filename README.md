# Purple Team lab — Attack & Detection

A hands-on purple team project where I built a controlled lab environment, executed real attacks across multiple vectors, then switched to the defensive side and detected every stage using Splunk, Suricata, and Sysmon. The goal was to develop both offensive and defensive skills simultaneously and document the full picture the way a SOC analyst or pentester would in a real engagement.

---

## Lab Topology

<img width="1536" height="1024" alt="Image" src="https://github.com/user-attachments/assets/0af13824-3130-4902-b940-74b4f5104e12" />

---

## Lab Environment

| Machine | IP | OS | Role |
|---------|----|----|------|
| Attacker | 192.168.56.102 / .110 | Kali Linux | Offensive operations |
| Target (Web/SSH) | 192.168.56.105 | Windows 10 + DVWA | Victim machine |

**Host-based monitoring:** Sysmon (Windows 10 target)
**Network monitoring:** Suricata IDS
**SIEM:** Splunk (ingesting Sysmon + Suricata + Web logs)

---

## Attack Scenarios

| # | Scenario | Offense Tool | Detection Sources | MITRE ATT&CK |
|---|----------|-------------|-------------------|--------------|
| 1 | Network Reconnaissance | Nmap | Suricata, Splunk | T1595.001, T1046 |
| 2 | SSH Brute Force | Hydra | Sysmon, Suricata | T1110.001, T1059 |
| 3 | SQL Injection | sqlmap | Web logs, Suricata | T1190, T1213 |
| 4 | Remote File Inclusion + Webshell | Custom PHP | Web logs, Suricata, Sysmon | T1190, T1505.003, T1059 |
| 5 | Windows Exploitation | Metasploit, GodPotato, Mimikatz | Sysmon | T1059, T1053.005, T1547.001, T1003, T1056.001 |


## Phase Summaries

### 01 — Network Reconnaissance
Ran a full SYN stealth scan across all 65,535 ports using Nmap with OS detection and aggressive timing. The scan generated 34,541 packets hitting 33,517 unique ports on the target. On the detection side, three independent Splunk queries confirmed the activity: port volume threshold, Suricata's direct Nmap signature match, and a time-based burst detection showing 200+ events per minute.


---

### 02 — SSH Brute Force
Used Hydra with username and password wordlists against the SSH service, successfully cracking the credentials `Admin / P@ssword123!` across 2,014 connection attempts. After logging in, ran `whoami`, `ipconfig`, and `net user` on the Windows target. Sysmon Event ID 3 caught the connection volume, Suricata fired its SSH brute force signature 830 times, and Sysmon Event ID 1 captured the post-login commands with full process paths.


---

### 03 — SQL Injection
Ran sqlmap against DVWA's SQLi endpoint in five progressive steps — confirming the injection point, enumerating databases, tables, and columns, then dumping the full users table including MD5-hashed credentials. sqlmap left multiple detection signals: URL-encoded UNION SELECT payloads in web logs, its own user agent string (`sqlmap/1.10.2#stable`), SQL keywords in query parameters, and a Suricata signature hit. Six Splunk queries documented the complete attack from first probe to credential dump.


---

### 04 — Remote File Inclusion + Webshell
Uploaded a PHP webshell (`RFI_bash.php`) through DVWA's file upload page and executed `whoami`, `ipconfig`, `systeminfo`, and `net user` on the Windows target via HTTP POST requests. The full attack took under 5 minutes from login to command execution. Suricata fired four distinct signatures including a WebShell command execution detection. Web logs captured the complete session timeline including varying response byte sizes that revealed which commands ran. Sysmon Event ID 1 confirmed OS-level execution with exact timestamps matching the web log entries.


---

### 05 — Windows Exploitation
The most involved phase. Used Metasploit to gain an initial reverse shell, achieved SYSTEM immediately via Named Pipe Impersonation, then worked through multiple persistence and post-exploitation techniques. Documented both successful and failed attempts including UAC bypass failures and a broken persistence payload (likely missing .NET dependency). Key activities: GodPotato execution, scheduled task persistence disguised as `WindowsUpdate`, HKLM Run key persistence, lsass migration, credential dumping with Mimikatz/Kiwi, PowerShell download cradle, keylogging, and screenshot capture.

Detection across nine Sysmon queries covered every stage. The most significant finding was `lsass.exe` appearing as the source of outbound connections and cmd.exe spawning after session migration — visible only because of Sysmon's parent-child process chain logging.


---

## Tools Used

| Category | Tools |
|----------|-------|
| Offensive | Nmap, Hydra, sqlmap, Metasploit Framework, msfvenom, GodPotato, Mimikatz (Kiwi) |
| Defensive | Sysmon, Suricata, Splunk |
| Target Application | DVWA (Damn Vulnerable Web Application) on XAMPP |

---

## Key Takeaways

Working both sides of the same attack repeatedly made a few things clear that are hard to learn any other way:

**Sysmon is the difference.** Without it, the Windows exploitation phase would have been almost entirely invisible to the SIEM. Default Windows logging doesn't capture command-line arguments, process parent chains, or network connections at the process level. Every meaningful detection in Phase 5 came from Sysmon.

**Layered detection beats single-source detection.** Every phase had at least two independent data sources confirming the same activity. When Suricata's Nmap signature fired and the Splunk port-volume query also triggered, that's a high-confidence finding — not a tuning candidate. Single-source alerts are easy to dismiss; correlated alerts across host and network are not.

**Failed attacks are worth documenting.** The UAC bypass failures and the broken port 4446 callback in Phase 5 are documented in detail because in a real engagement, failed attempts tell you about the environment — missing dependencies, patched vulnerabilities, unexpected configurations. A report that only shows successes isn't an honest picture of what happened.

**Attackers leave more signals than they think.** sqlmap's user agent string, the lsass migration footprint, the schtasks command line captured verbatim — none of these required advanced detection engineering. They were all there in the default Sysmon + Suricata configuration. The gap in most environments isn't detection capability, it's log collection and someone looking.

---

## 📹 Full Lab Walkthrough

🎥 [Watch the complete video demonstration](#) https://www.youtube.com/playlist?list=PLyvuyjd57e75N5De-CX6oE3L3YIkR80Qe

