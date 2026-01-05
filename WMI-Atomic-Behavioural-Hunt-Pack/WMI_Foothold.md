## Introduction — How Attackers Gain the Foothold That Enables WMI Abuse

WMI-based attacks **do not happen in isolation**. By the time WMI is abused for execution or persistence, the attacker has already achieved an **initial foothold** and is operating with sufficient privileges to interact with WMI namespaces, COM objects, or remote systems.

Understanding **how attackers arrive at the WMI stage** is critical for correct threat modeling and for explaining this ecosystem during interviews or design reviews.

This section documents the **most common real-world footholds** that precede the WMI attack ecosystem covered in this repository.

---

## 1. Initial Access Vectors (Pre-WMI)

WMI is rarely used for *initial* access. It is a **post-compromise capability amplifier**. Common entry points include:

### 1.1 Phishing & User Execution
- Malicious Office documents (VBA, XLM, ISO/LNK delivery)
- HTML smuggling or ZIP-based payload delivery
- Initial payload often launches via:
  - `mshta.exe`
  - `powershell.exe`
  - `rundll32.exe`
  - `wscript.exe / cscript.exe`

**Outcome:**  
User-level code execution → credential harvesting → escalation → WMI abuse.

---

### 1.2 Exploited Public-Facing Services
- IIS / web application vulnerabilities
- Deserialization bugs
- API injection (JSON/YAML/GraphQL)
- Misconfigured admin panels

**Outcome:**  
Webshell or in-memory loader → SYSTEM or service account → WMI persistence or lateral movement.

---

### 1.3 Supply Chain / Signed Binary Abuse
- Trojanized installers
- Signed loaders abusing LOLBins
- MSI / update channel compromise

**Outcome:**  
Trusted execution context → stealthy WMI-based persistence to survive reboots.

---

## 2. Privilege Escalation (Why WMI Becomes Available)

WMI abuse **usually requires elevated privileges**:

- Local Administrator
- SYSTEM
- Domain Admin (for lateral WMI)

Common escalation paths:
- Token theft
- UAC bypass
- Exploited drivers (BYOVD)
- Credential dumping (LSASS, SAM, DPAPI)

Once elevated, WMI becomes attractive because:
- It is trusted
- It blends with admin activity
- It requires no new binaries

---

## 3. Credential Access & Lateral Enablement

Before WMI lateral movement, attackers often steal credentials via:
- LSASS dumping
- Browser credential theft
- Kerberos ticket abuse
- Cached admin credentials on endpoints

These credentials enable:
- `wmic /node:`
- `Invoke-WmiMethod -ComputerName`
- DCOM-based remote execution

**Key Insight:**  
WMI lateral movement is often the **first “quiet” lateral step** before noisier techniques like SMB exec or PsExec.

---

## 4. Why Attackers Choose WMI After Foothold

Once inside, WMI offers attackers:

| Capability | Why It’s Valuable |
|---|---|
| Native execution | No dropped binaries |
| Remote process creation | Lateral movement without SMB tools |
| Event-based persistence | Survives reboot without startup files |
| Script execution | VBScript/JScript without PowerShell |
| Process-less execution | Bypasses process-based EDR logic |

This makes WMI ideal for **long-term access**, **low-noise persistence**, and **APT-style operations**.

---

## 5. Mapping Foothold → WMI Attack Lifecycle

~~~
Initial Access
↓
User Execution / Exploit
↓
Privilege Escalation
↓
Credential Access
↓
WMI Abuse Begins
├─ Recon (Win32_* queries)
├─ Remote Execution (Win32_Process Create)
├─ Persistence (Event Subscriptions)
└─ Fileless Execution (ActiveScriptEventConsumer)
~~~


This repository focuses on everything **after** the foothold — where traditional SOC visibility often drops off.

---

## 6. Why This Matters for Detection Architecture

Most detection programs over-invest in:
- Initial access detections
- Malware signatures
- Child process relationships

And under-invest in:
- Post-compromise living-off-the-land tradecraft
- Fileless persistence
- Long-dwell attacker behavior

WMI sits **squarely in that blind spot**.

The rules and architecture documented here are designed to detect attackers who:
- Already bypassed email security
- Already evaded endpoint prevention
- Are now trying to **stay**.

---

## 7. Key Takeaway

If you are detecting WMI abuse:
- **You are already late** — and that’s okay.
- Your job is no longer prevention.
- Your job is **exposure, containment, and eviction**.

This repository exists to ensure that once an attacker reaches the WMI stage,  
**they do not remain invisible.**
