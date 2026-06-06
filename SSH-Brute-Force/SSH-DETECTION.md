# SSH Brute Force — Detection

After the attack I switched to the blue team side to detect both the brute force attempt and the post-login activity. The target was a Windows 10 machine with Sysmon installed, so I had both host-level visibility via Sysmon and network-level visibility via Suricata — giving me three distinct detection angles on the same attack.

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing | T1059 — Command and Scripting Interpreter

---

## Environment

| | IP | OS |
|---|---|---|
| Attacker | 192.168.56.102 | Kali Linux |
| Target | 192.168.56.105 | Windows 10 (Sysmon installed) |

---

## Detection 1 — High Volume SSH Connections (Sysmon Event ID 3)

Sysmon Event ID 3 logs outbound and inbound network connections on the Windows host. A legitimate user doesn't establish 2,000+ SSH connections — that volume only comes from automated tooling hitting the machine repeatedly.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 dest_port=22
| stats count as connections by src_ip, dest_ip
| where connections > 10
```

**Result:** `192.168.56.102 → 192.168.56.105` with **2,014 connections** on port 22 — a clear brute force pattern from a single source recorded directly on the Windows host.

> 📸 `screenshots/detection1-sysmon-ssh-connections.png`

---

## Detection 2 — Suricata SSH Brute Force Signature

Suricata flagged the traffic at the network layer using its SSH brute force detection rule, independently of what Sysmon saw on the host. Having both agree is a strong confirmation.

```spl
index=suricata event_type=alert alert.signature="*SSH*"
| stats count by src_ip, dest_ip, alert.signature
| sort -count
```

**Result:** `192.168.56.102 → 192.168.56.105` with the signature **"SSH Bruteforce — T1110"** firing **830 times**. The difference between 2,014 Sysmon events and 830 Suricata alerts is expected — Suricata aggregates before alerting while Sysmon logs every individual connection event.

> 📸 `screenshots/detection2-suricata-ssh-signature.png`

---

## Detection 3 — Post-Login Command Execution (Sysmon Event ID 1)

Once the brute force succeeded and I logged in, I ran `whoami`, `ipconfig`, and `net user` on the Windows target. Sysmon Event ID 1 captures process creation with the full command line, making it one of the best events for catching what an attacker did after gaining access.

```spl
index=* EventCode=1
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*ipconfig*"
```

**Result:** 2 events returned — `whoami` and `ipconfig` — confirming execution on the Windows host after successful login. This directly ties back to the brute force alerts above and completes the attack timeline.

> 
<img width="1896" height="604" alt="Image" src="https://github.com/user-attachments/assets/288dc967-1e79-4733-9a14-3cb68c5319a8" />
<img width="1893" height="851" alt="Image" src="https://github.com/user-attachments/assets/20779682-67e2-45d9-a4da-07fc411a8cc1" />

---

## Summary

| Detection | Source | Signal | Result |
|-----------|--------|--------|--------|
| High-volume SSH connections | Sysmon Event ID 3 (Windows host) | 2,014 connections on port 22 | Confirmed brute force |
| SSH brute force signature | Suricata (network layer) | 830 signature hits — T1110 | Confirmed brute force |
| Post-login commands | Sysmon Event ID 1 (Windows host) | `whoami`, `ipconfig` executed | Confirmed successful login |

The detection chain here tells the full story — the first two queries catch the brute force attempt from two independent sources (host and network), and the third confirms the login succeeded by showing hands-on command execution on the Windows machine. In a real SOC environment this progression from alert to confirmed compromise is exactly what an analyst would document in an incident report.

---

## 📹 Video Demonstration

🎥 *[Watch](https://www.youtube.com/watch?v=MoEo8Rg9VN8&list=PLyvuyjd57e75N5De-CX6oE3L3YIkR80Qe&index=5&t=52s)*

---
