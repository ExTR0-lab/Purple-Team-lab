# Remote File Inclusion (RFI) — Detection

After the attack I investigated using three data sources: Suricata for network-layer alerts, web logs for the full HTTP activity timeline, and Sysmon for the host-level command execution. Together they cover the attack from upload to OS command execution.

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application | T1505.003 — Web Shell | T1059 — Command and Scripting Interpreter

---

## Environment

| | IP | OS |
|---|---|---|
| Attacker | 192.168.56.102 | Kali Linux |
| Target (DVWA) | 192.168.56.105 | Windows 10 (Sysmon installed) |

---

## Detection 1 — Suricata Multi-Signature Alerts

The first place I looked was Suricata to see what the network layer caught. This query groups all alerts by source IP and signature to show the full picture at once.

```spl
index=suricata event_type="alert"
| stats count by src_ip alert.signature
| sort -count
```

**Result:** Four distinct signatures fired against `192.168.56.102`:

| alert.signature | count |
|-----------------|-------|
| RFI - IP address in HTTP request | (your count) |
| RFI - PHP file remotely included via http | (your count) |
| Debug - HTTP traffic seen | 9 |
| WebShell - Command execution parameter detection | 7 |

What stands out here is the progression — Suricata caught the RFI pattern in the request, then independently detected command execution parameters being passed to the webshell. That's two separate stages of the attack flagged at the network layer alone.

> 📸 <img width="1905" height="702" alt="Image" src="https://github.com/user-attachments/assets/b7c654c5-03c2-41cb-8826-9233ace9e80e" />

---

## Detection 2 — Web Log Activity by URI Path

This query gives a count of all requests from the attacker grouped by path and method, making it easy to spot which endpoints were most active.

```spl
index=Web_log src_ip="192.168.56.102"
| stats count by uri_path method status
| sort -count
```

**Result:**

| uri_path | method | status | count |
|----------|--------|--------|-------|
| /dvwa/hackable/uploads/RFI_bash.php | POST | 200 | 6 |
| /dvwa/security.php | GET | 200 | 2 |
| /dvwa/vulnerabilities/upload/ | POST | 200 | 1 |
| /dvwa/hackable/uploads/RFI_bash.php | GET | 200 | 1 |
| /dvwa/hackable/uploads/RFI_bash.ph | GET | 404 | 1 |

The six POST requests to `RFI_bash.php` are the webshell commands being executed. The 404 on `RFI_bash.ph` shows the attacker made a typo on the first access attempt — a detail that's useful in a real investigation for confirming manual interaction rather than fully automated tooling.

> 📸 `screenshots/detection2-uri-activity.png`

---

## Detection 3 — Webshell Request Timeline

Filtering specifically on the webshell file shows the byte sizes of each response, which reveals what the commands returned.

```spl
index=Web_log src_ip="192.168.56.102" uri_path="*RFI_bash.php"
| table _time method uri_path status bytes
| sort _time
```

**Result:**

| Time | Method | Status | Bytes |
|------|--------|--------|-------|
| 13:40:31 | GET | 200 | 10,879 |
| 13:40:32 | POST | 200 | 17 |
| 13:40:37 | POST | 200 | 36 |
| 13:40:42 | POST | 200 | 755 |
| 13:40:53 | POST | 200 | 3,314 |
| 13:41:06 | POST | 200 | 381 |
| 13:41:11 | POST | 200 | 565 |

The initial GET (10,879 bytes) is the webshell UI loading. The POST requests that follow are commands being sent — the varying response sizes reflect different command outputs. The 3,314-byte response at 13:40:53 corresponds to `systeminfo`, which returns the most data. This byte-size pattern is a reliable way to infer what commands were run even without seeing the request body directly.

> 📸 `screenshots/detection3-webshell-timeline.png`

---

## Detection 4 — Full Attacker Session Timeline

This query reconstructs the attacker's complete session from first request to last command, including referrer headers which show navigation flow.

```spl
index=Web_log src_ip="192.168.56.102"
| table _time method uri_path uri_query status bytes referer
| sort _time
```

**Result — Full timeline:**

| Time | Method | URI Path | Status | Bytes |
|------|--------|----------|--------|-------|
| 13:36:49 | GET | /dvwa/hackable/uploads/ | 200 | 819 |
| 13:37:00 | GET | /dvwa/login.php | 200 | 1,342 |
| 13:37:03 | POST | /dvwa/login.php | 302 | 136 |
| 13:37:03 | GET | /dvwa/index.php | 200 | 6,530 |
| 13:38:14 | GET | /dvwa/security.php | 200 | 5,188 |
| 13:38:19 | POST | /dvwa/security.php | 302 | 136 |
| 13:40:07 | GET | /dvwa/vulnerabilities/upload/ | 200 | 4,514 |
| 13:40:17 | POST | /dvwa/vulnerabilities/upload/ | 200 | 4,582 |
| 13:40:26 | GET | /dvwa/hackable/uploads/RFI_bash.ph | 404 | 1,059 |
| 13:40:31 | GET | /dvwa/hackable/uploads/RFI_bash.php | 200 | 10,879 |
| 13:40:32–13:41:11 | POST | /dvwa/hackable/uploads/RFI_bash.php | 200 | varies |

The referer headers confirm the natural navigation flow — each page linked from the previous one, showing deliberate manual movement through the application rather than random fuzzing.

> 📸 `screenshots/detection4-full-timeline.png`

---

## Detection 5 — Upload Directory Monitoring

Monitoring access to the uploads directory specifically catches both the pre-attack reconnaissance and the post-upload webshell access.

```spl
index=Web_log uri_path="*/hackable/uploads/*"
| table _time src_ip uri_path method status
| sort _time
```

**Result:**

| Time | src_ip | uri_path | method | status |
|------|--------|----------|--------|--------|
| 13:36:49 | 192.168.56.102 | /dvwa/hackable/uploads/ | GET | 200 |
| 13:40:26 | 192.168.56.102 | /dvwa/hackable/uploads/RFI_bash.ph | GET | 404 |
| 13:40:31 | 192.168.56.102 | /dvwa/hackable/uploads/RFI_bash.php | GET | 200 |
| 13:40:32 | 192.168.56.102 | /dvwa/hackable/uploads/RFI_bash.php | POST | 200 |
| 13:40:37–13:41:11 | 192.168.56.102 | /dvwa/hackable/uploads/RFI_bash.php | POST | 200 |

In a production environment, any GET or POST request directly to a file in an uploads directory should be treated as suspicious. Upload directories should store files, not execute them — this single alert rule would catch the attack at the moment of webshell access.

> 📸 `screenshots/detection5-uploads-directory.png`

---

## Detection 6 — Host-Level Command Execution (Sysmon Event ID 1)

This is where host and network detections meet. Sysmon Event ID 1 on the Windows target captured every command executed through the webshell, including the full executable path and command line.

```spl
index=sysmon EventCode=1 ParentImage="*cmd*"
| table _time Image CommandLine
| sort _time
```

**Result:**

| Time | Image | CommandLine |
|------|-------|-------------|
| 13:40:37 | C:\Windows\System32\whoami.exe | whoami |
| 13:40:42 | C:\Windows\System32\ipconfig.exe | ipconfig |
| 13:40:54 | C:\Windows\System32\systeminfo.exe | systeminfo |
| 13:41:06 | C:\Windows\System32\net.exe | net user |

The timestamps here align exactly with the POST requests in the web log — `whoami` at 13:40:37 matches the 36-byte web log response, `systeminfo` at 13:40:54 matches the 3,314-byte response. This cross-source correlation between web logs and Sysmon is exactly how a SOC analyst would confirm that web requests resulted in actual OS command execution on the host.

> 📸 `screenshots/detection6-sysmon-commands.png`

---

## Summary

| Detection | Source | Signal | Stage Caught |
|-----------|--------|--------|--------------|
| Multi-signature alerts | Suricata | RFI + WebShell signatures | Upload + execution |
| URI activity by path | Web log | 6 POSTs to uploaded PHP file | Webshell usage |
| Webshell request timeline | Web log | Varying byte sizes per command | Command execution inferred |
| Full attacker session | Web log | Complete navigation flow with referrers | Entire attack chain |
| Uploads directory access | Web log | Direct file execution in uploads path | Webshell access |
| Host command execution | Sysmon Event ID 1 | whoami, ipconfig, systeminfo, net user | OS-level RCE confirmed |

The most valuable finding here is the Sysmon-to-web-log correlation — matching timestamps and response sizes across two independent data sources confirms that the HTTP requests in the web log translated directly into process execution on the Windows host. That cross-source correlation is what turns an alert into a confirmed incident.

---

## 📹 Video Demonstration

🎥 [Watch](#) *(add link)*

---

## Screenshots

| File | What it shows |
|------|--------------|
| `screenshots/detection1-suricata-signatures.png` | 4 Suricata signatures from attacker IP |
| `screenshots/detection2-uri-activity.png` | Request counts grouped by URI and method |
| `screenshots/detection3-webshell-timeline.png` | POST requests with byte sizes per command |
| `screenshots/detection4-full-timeline.png` | Complete 20-event attacker session |
| `screenshots/detection5-uploads-directory.png` | All uploads directory access events |
| `screenshots/detection6-sysmon-commands.png` | 4 commands executed on Windows host |
