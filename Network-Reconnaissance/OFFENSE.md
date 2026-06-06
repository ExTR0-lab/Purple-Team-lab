# Network Reconnaissance — Offense

In this phase I performed a full port scan against the target machine to identify all open ports, running services, and the operating system before moving to exploitation.

**MITRE ATT&CK:** T1595.001 — Active Scanning | T1046 — Network Service Discovery

---

## Environment

| | IP |
|---|---|
| Attacker (Kali) | 192.168.56.102 |
| Target | 192.168.56.105 |

---

## Command

```bash
nmap -sS -T4 -O -p- -oN attack.txt 192.168.56.105
```

I used a SYN stealth scan across all 65,535 ports with aggressive timing to keep the scan fast, combined with OS detection to fingerprint the target. Results were saved to `attack.txt` for reference during later exploitation phases.

| Flag | Purpose |
|------|---------|
| `-sS` | SYN stealth scan — never completes the TCP handshake, faster and quieter |
| `-T4` | Aggressive timing — reduces delays between probes |
| `-O` | OS fingerprinting via TCP/IP stack behavior |
| `-p-` | All 65,535 ports, not just the default top 1000 |
| `-oN attack.txt` | Save output to file |

---

## Result

The scan returned **33,517 open ports** across **34,541 total packets**, confirming the target had a large attack surface. OS detection successfully fingerprinted the system, which fed directly into exploit selection in the Metasploit phase.

---

## 📹 Video Demonstration

🎥 [Watch](#) *([add link](https://youtu.be/TVthhLdR4Vo?si=8pt824FXH0R6lG_8))*

---

## Screenshots

><img width="825" height="542" alt="Image" src="https://github.com/user-attachments/assets/9ad4419c-2423-4fda-9a7f-9a1adbd3e492" />
