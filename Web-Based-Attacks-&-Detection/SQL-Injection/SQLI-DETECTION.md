# SQL Injection — Detection

After completing the attack I moved to Splunk to investigate the web logs and Suricata alerts. sqlmap generates very distinctive traffic patterns — the URL-encoded payloads, the tool's user agent string, and the sheer request volume all make it detectable from multiple angles.

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application | T1213 — Data from Information Repositories

---

## Environment

| | IP |
|---|---|
| Attacker | 192.168.56.102 |
| Target (DVWA) | 192.168.56.105 |

---

## Detection 1 — SQLi URI Path Activity

The first query I ran was a broad look at all traffic hitting the SQLi endpoint, sorted by time. This gives a chronological view of exactly what the attacker was doing and when.

```spl
index=Web_log uri_path="*/sqli/*"
| table _time src_ip method uri_path status
| sort _time
```

**Result:** All requests came from `192.168.56.102` via GET method to `/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit`. Mixed in with the clean requests were heavily URL-encoded payloads — sqlmap's UNION-based injection strings targeting `INFORMATION_SCHEMA` to enumerate databases, tables, and columns. A few examples from the results:

```
/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit
/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20CONCAT(...)%20FROM%20INFORMATION_SCHEMA.SCHEMATA
/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20CONCAT(...)%20FROM%20INFORMATION_SCHEMA.TABLES
/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20CONCAT(...)%20FROM%20INFORMATION_SCHEMA.COLUMNS
```

The URL encoding (`%27` = `'`, `%20` = space) is standard sqlmap behaviour — when decoded these are clear UNION SELECT injection attempts against the database schema.

> <img width="1919" height="806" alt="Image" src="https://github.com/user-attachments/assets/fe7716b1-95ec-4096-8e81-be49a966ec02" />

---

## Detection 2 — Request Volume from Single Source

A quick count of how many times the SQLi endpoint was hit by each source IP.

```spl
index=Web_log uri_path="*/sqli/*"
| stats count by src_ip
| sort -count
```

**Result:** `192.168.56.102` made **10 requests** to the SQLi path. That might seem low, but sqlmap is efficient — it only sends what it needs to per step. Combined with the payload content in Detection 1, the volume and the content together confirm automated tooling.

> <img width="1920" height="714" alt="Image" src="https://github.com/user-attachments/assets/7fa7d242-778c-42a2-a22c-031b19d005a1" />

---

## Detection 3 — sqlmap User Agent

sqlmap sends a recognisable user agent string in every request. This query catches it directly.

```spl
index=Web_log user_agent="*sqlmap*"
| table _time src_ip user_agent uri_query
| sort _time
```

**Result:** `192.168.56.102` with user agent `sqlmap/1.10.2#stable (https://sqlmap.org)`. The `uri_query` column shows the same long UNION-based payloads from Detection 1 — confirming the tool, the attacker IP, and the exact queries it sent all in one result.

This is the simplest and most direct detection. In a real environment blocking or alerting on the sqlmap user agent string is a quick win.

> <img width="1920" height="872" alt="Image" src="https://github.com/user-attachments/assets/c65e3f27-eca4-4a24-9875-1be7214d71aa" />

---

## Detection 4 — SQL Keyword Detection in Query Strings

This query looks for common SQL injection keywords in the URI query parameters — useful for catching injection attempts regardless of what tool was used.

```spl
index=Web_log
(uri_query="*UNION*" OR uri_query="*SELECT*" OR uri_query="*AND 1=1*" OR uri_query="*ORDER BY*" OR uri_query="*information_schema*")
| table _time src_ip uri_query
| sort _time
```

**Result:** All hits came from `192.168.56.102`. The `uri_query` values were the same long URL-encoded UNION SELECT strings seen in previous queries — confirming that keyword-based detection independently catches the same attack without relying on user agent or path matching.

> <img width="1915" height="512" alt="Image" src="https://github.com/user-attachments/assets/a87dac7e-c16d-409f-a5f1-39e8608eb17f" />

---

## Detection 5 — Suricata sqlmap Signature

Suricata detected the sqlmap user agent at the network layer through its own rule set, independent of the web logs.

```spl
index=suricata alert.signature="sqlmap UA"
| stats count by src_ip dest_ip http.uri alert.signature
| sort -count
```

**Result:** `192.168.56.102 → 192.168.56.105` with signature **"sqlmap UA"** — the same attack confirmed at the network level. The `http.uri` field showed the same injection payloads, and the count reflects how many times Suricata fired the rule across the full attack.

> <img width="1700" height="500" alt="Image" src="https://github.com/user-attachments/assets/ee9b0a9d-55a8-40f6-95a7-5d26ec0c0ca6" />

---

## Detection 6 — Full Attacker Timeline

After confirming the attack across multiple queries I built a full chronological timeline of everything the attacker's IP did against the web server.

```spl
index=Web_log src_ip="192.168.56.102"
| table _time method uri_path uri_query status
| sort _time
```

**Result:** A complete picture of the attack chain in order — initial probe requests, then progressively more complex UNION payloads targeting schema enumeration, then table and column discovery, then the final data dump query. The HTTP status codes in the `status` column confirm which requests received valid responses from the server.

This is the query an analyst would run after the others to document the full incident timeline.

> <img width="1910" height="777" alt="Image" src="https://github.com/user-attachments/assets/c2b4efde-c82d-4e5b-ac0e-64021bd8dd11" />

---

## Summary

| Detection | Source | Signal | What It Catches |
|-----------|--------|--------|-----------------|
| SQLi URI path activity | Web log | UNION payloads in URL | Attack content |
| Request volume | Web log | 10 hits on SQLi endpoint | Automated pattern |
| sqlmap user agent | Web log | `sqlmap/1.10.2#stable` | Tool identification |
| SQL keyword detection | Web log | UNION, SELECT, information_schema in query | Payload keywords |
| Suricata sqlmap signature | Suricata | "sqlmap UA" rule fired | Network-layer confirmation |
| Full attacker timeline | Web log | Complete request history from attacker IP | Incident documentation |

What stands out here is how many independent signals sqlmap leaves behind. Even if an attacker changed their user agent, the SQL keywords in the URL and the Suricata network signature would still catch it. Layered detection across web logs and network IDS means there's no single point of failure.

---

## 📹 Video Demonstration

🎥 [Watch](#) *(add link)*

---

## Screenshots

| File | What it shows |
|------|--------------|
| `screenshots/detection1-sqli-uri-path.png` | Decoded UNION payloads in URI path |
| `screenshots/detection2-request-count.png` | 10 requests from attacker IP |
| `screenshots/detection3-sqlmap-useragent.png` | sqlmap/1.10.2 user agent string |
| `screenshots/detection4-sql-keywords.png` | SQL keywords in uri_query |
| `screenshots/detection5-suricata-sqlmap.png` | Suricata sqlmap UA rule |
| `screenshots/detection6-full-timeline.png` | Full chronological attack timeline |
