# Network Reconnaissance — Detection

After running the scan I moved to the blue team side and built three Splunk queries on top of Suricata logs to detect the activity. The goal was to show how a SOC analyst would catch this in a real environment.

**MITRE ATT&CK:** T1595.001 — Active Scanning | T1046 — Network Service Discovery

---

## Environment

| | IP |
|---|---|
| Attacker | 192.168.56.102 |
| Target | 192.168.56.105 |

---

## Detection 1 — Port Scan Volume

The first thing I looked for was an unusually high number of unique destination ports from a single source. Any host touching more than 100 ports isn't browsing — it's scanning.

```spl
index=suricata
| stats dc(dest_port) as scanned_ports count by src_ip, dest_ip
| where scanned_ports > 100 AND count > 100
```

**Result:** `192.168.56.102` hit `192.168.56.105` across **33,517 unique ports** with **34,541 total events** — a clear full-port sweep.

> <img width="1306" height="553" alt="Image" src="https://github.com/user-attachments/assets/1631f665-7a57-461b-ae1b-bf19d288de88" />

---

## Detection 2 — Nmap Signature Alert

Suricata has built-in rules that match Nmap's TCP fingerprint. This query surfaced those direct signature hits.

```spl
index=suricata event_type=alert alert.signature="*Nmap*"
| table _time src_ip dest_ip alert.signature
```

**Result:** Multiple rows showing `192.168.56.102 → 192.168.56.105` with the signature **"Nmap SYN Scan Detected — T1046"** firing across different destination ports, confirming the tool used by the attacker.

><img width="1287" height="808" alt="Image" src="https://github.com/user-attachments/assets/5cd60f78-813d-49c8-acbe-f3c3c3662742" />

---

## Detection 3 — Burst Rate (Time-Based)

The third query bins traffic into 1-minute windows to catch the aggressive timing pattern. Nmap `-T4` generates traffic in fast bursts that stand out clearly when windowed.

```spl
index=suricata
| bin _time span=1m
| stats count by src_ip, dest_ip, _time
| where count > 200
```

**Result:** The same source-destination pair produced **200+ events within a single minute**, consistent with `-T4` aggressive timing behavior.

> <img width="1299" height="527" alt="Image" src="https://github.com/user-attachments/assets/af384127-1327-4f36-a10d-0b8309174495" />

---

## Summary

Three independent signals — all pointing to the same attacker IP:

| Detection | Signal | Confidence |
|-----------|--------|------------|
| Port volume | 33,517 unique ports from one source | High |
| Nmap signature | Suricata matched the TCP fingerprint directly | High |
| Burst rate | 200+ events/min in a 1-minute window | High |

Having all three line up is what makes this a high-confidence detection rather than a false positive. In a real SOC this would warrant immediate investigation of what came after the scan.

---

## 📹 Video Demonstration

🎥 [Watch](#) *(add link)*

---
