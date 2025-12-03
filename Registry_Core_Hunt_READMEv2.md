# Advanced Registry Persistence Detection  
**Author:** Ala Dabat  
**Category:** Persistence / Execution Hijacking / Defence Evasion  
**Platform:** Microsoft Defender for Endpoint / Microsoft Sentinel  
**Version:** Engineering Pack – Behaviour-Driven Model  

This module documents the complete behavioural model behind the Registry Persistence Detection analytic.  
It includes MITRE ATT&CK mappings, coverage matrices, IOC examples, SOC pivots, and triage workflows.

This is a high-fidelity detection artefact designed for Tier-2, Tier-3 and Threat Hunting teams.

---

# 1. Overview

The Windows Registry remains one of the most abused persistence and execution hijack surfaces.  
Modern malware, red-team tools, loaders, and APT tradecraft routinely leverage:

- **Run / RunOnce keys**
- **IFEO (Image File Execution Options) hijacking**
- **Winlogon Shell / Userinit replacement**
- **Active Setup**
- **AppInit_DLLs**
- **COM Hijacking (InProcServer32)**
- **LSA Plugin modification**
- **Service ImagePath tampering**
- **User-writable persistence paths**
- **LOLBin-driven script execution**
- **Encoded PowerShell stagers / proxy loaders**

This analytic uses multi-signal scoring, path analysis, publisher validation, and prevalence metrics  
to identify malicious activity while suppressing benign enterprise noise.

---

# 2. MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **TA0002 – Execution** | T1059 (PowerShell), T1218 (LOLBAS), T1047 (WMI Exec) | Registry keys chaining into script or binary execution |
| **TA0003 – Persistence** | T1547.001 (Run Keys), T1547.009 (LSA), T1546.012 (IFEO), T1546.015 (COM Hijacking), T1543.003 (Service ImagePath) | Core registry persistence families |
| **TA0004 – Privilege Escalation** | T1546 (Hijacking), T1543 (Service tampering) | Elevated persistence vectors |
| **TA0005 – Defense Evasion** | T1218 (LOLBAS), unsigned binaries, encoded payloads, hidden staging paths | Obfuscation and EDR bypass |
| **TA0006 – Credential Access** | T1556 (LSA Plugins), T1003 (Credential theft via hijacks) | Registry-based credential interception |
| **TA0011 – C2 & Exfiltration** | T1105 (ingress tool transfer via registry-stored URLs/IPs) | Network-enabled persistence |

---

# 3. Threat Coverage Matrix

| Threat Category | Detected | Notes |
|-----------------|----------|-------|
| Run / RunOnce autoruns | ✔ | High-risk when pointing to rare/unsigned payloads |
| IFEO Debugger Hijack | ✔ | Detects debugger redirection → RAT/loader chains |
| Winlogon Shell / Userinit | ✔ | Critical paths, rare legitimate activity |
| Active Setup & Installed Components | ✔ | Used by Emotet, Qakbot, FIN7 |
| COM Hijacking (InProcServer32) | ✔ | DLL hijacks and tradecraft used by APT29, Turla |
| LSA Plugin Injection | ✔ | Credential harvesting / SSP modification |
| Service ImagePath / FailureCommand | ✔ | Persistence and execution hijack |
| AppInit_DLLs | ✔ | Rare in modern systems → high signal |
| URL/IP-based persistence | ✔ | Registry chains linking to C2 |
| User-writable path persistence | ✔ | AppData/Public/Temp abuse |
| Browser extension persistence | ✘ | Different surface (separate rule) |
| Startup folder entries | ✘ | Not registry-based |

---

# 4. IOC Catalogue (Examples)

| IOC Type | Example Indicators |
|----------|--------------------|
| Suspicious Run Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater = %APPDATA%\update.exe` |
| Encoded PowerShell | `powershell.exe -EncodedCommand JAB…` |
| Network-backed persistence | Registry value referencing `hxxp://malicious[.]domain/payload.ps1` |
| IFEO Hijack | `HKLM\...\Image File Execution Options\notepad.exe\Debugger = "cmd.exe /c payload.exe"` |
| Winlogon Shell Manipulation | `Shell = explorer.exe, payload.exe` |
| COM Hijack | `HKCR\CLSID\{GUID}\InProcServer32 = C:\Users\Public\evil.dll` |
| LSA Plugin Injection | `HKLM\SYSTEM\CCS\Control\Lsa\Security Packages = evil.dll` |

---

# 5. Behavioural Detection Logic

The rule identifies malicious behaviour using:

### 5.1 Binary Legitimacy Tests
- Unsigned or unknown publisher  
- File located in AppData, ProgramData, Temp, Public  
- Prevalence ≤ 2 devices in the organisation  
- Non-Microsoft publishers where Microsoft binaries are expected  

### 5.2 Data Payload Inspection
- Executables/scripts referenced in registry values  
- URLs, IP addresses, encoded blobs  
- Suspicious extensions: `.dll`, `.js`, `.vbs`, `.ps1`, `.hta`, `.exe`  
- Base64 payloads, stagers, inline commands  

### 5.3 LOLBin Abuse Detection
Flags registry entries invoking:

- `mshta.exe`
- `rundll32.exe`
- `regsvr32.exe`
- `certutil.exe`
- `powershell.exe` (obfuscated)
- `bitsadmin.exe`
- `cmd.exe` → script loaders  

### 5.4 Privileged Key Abuse
Automatic high-severity when modifications occur in:

- Winlogon  
- LSA  
- AppInit_DLLs  
- IFEO  
- Services  

### 5.5 Scoring
Composite scoring criteria includes:

- Path risk  
- Prevalence  
- Publisher trust  
- LOLBin presence  
- Encoded commands  
- Presence of network references  
- Key sensitivity (Winlogon/IFEO/LSA etc.)

---

# 6. Analyst Triage Workflow

### Step 1 — Validate Initiating Process
- Check publisher, signer, and file reputation  
- If unsigned or rare → HIGH signal  
- If launched by a known LOLBin → likely malicious

### Step 2 — Review Registry Value Data
Look for:
- URLs  
- IP addresses  
- Base64 blobs  
- PowerShell stagers  
- Unknown executables in user-writable paths  
- DLLs in unexpected COM/LSA/IFEO keys  

### Step 3 — Evaluate Prevalence
- Is the binary seen on more than 2 devices?  
- Low prevalence strongly indicates malicious tooling.

### Step 4 — Correlate Process Execution
Pivot on:
```kql
DeviceProcessEvents
| where FileName =~ "<SuspiciousBinary>"

```
# 6. Analyst Workflow, Pivots & Triage Procedures (Steps 6–9 Consolidated)

This section provides a complete analyst workflow for investigating registry-based persistence, along with deep pivot guidance and validation steps used in L2/L3 SOC and Incident Response.

---

## 6.1 Event Validation & Initial Classification

**Objective:** Determine whether the registry modification represents legitimate software behaviour or a malicious foothold.

**Actions:**
- Check the **initiating process** (signer, company, file path, hash reputation, prevalence).
- Validate whether the registry path is expected for any installed application.
- Review **ValueData** for suspicious execution paths such as:
  - `%APPDATA%`, `%PUBLIC%`, `%TEMP%`
  - URLs, IPs, or `.ps1/.vbs/.dll/.exe` payloads
  - Encoded commands (Base64)
- Confirm whether the change was performed by **administrative context**, which increases threat value.

**Pivots:**
- `DeviceProcessEvents` around the timestamp  
- `DeviceNetworkEvents` for any payload retrieval  
- `DeviceImageLoadEvents` for DLL persistence abuse  
- `IdentityLogonEvents` for compromised accounts tied to registry actions  

---

## 6.2 Process Tree Reconstruction

**Objective:** Build a reliable picture of how the registry key was created or modified.

**Pipeline:**
1. Start from the `InitiatingProcessFileName` and timestamp.
2. Collect parent → child → grandchild lineage using:
   - `InitiatingProcessParentFileName`
   - `ProcessId` / `InitiatingProcessId`
   - `ReportId` continuity
3. Identify:
   - Scripted loaders (`powershell.exe -enc`, `cmd.exe /c curl`)
   - Loader chains (`mshta → rundll32 → regsvr32`)
   - Sideloaded binaries or unsigned DLLs
   - Uncommon or rare binaries (`LocalPrevalence ≤ 2`)

**High-value pivots:**
- `DeviceProcessEvents` (PID lineage and command lines)
- `DeviceFileEvents` (payload creation before registry persistence)
- `DeviceNetworkEvents` (stager download → registry installation)

---

## 6.3 Payload & Path Validation

**Objective:** Determine whether the referenced payload is malicious, staged, or unknown.

**Checks:**
- Is the referenced executable/dll **signed and trusted**?
- Was the file **recently created** or modified within ±2 minutes of registry event?
- Does the path contain:
  - `%TEMP%` / `%APPDATA%` / `ProgramData`
  - Public writable directories
  - Hidden subfolders
- Does the **SHA256** hash appear:
  - Rare across environment?
  - Rare across global reputation?
  - In any threat-intel dataset?

**Pivots:**
- `DeviceFileEvents` for creation timestamps  
- `DeviceFileCertificateInfo` for signer trust  
- `FileProfile` for prevalence & reputation  
- VT/Hybrid-Analysis lookup using SHA256  

---

## 6.4 Cross-Signal Correlation

**Objective:** Confirm that persistence is truly malicious by correlating multiple behaviours.

Legitimate software rarely triggers *multiple* suspicious surfaces at the same time.

**Cross-signal indicators include:**
- Registry persistence **+** suspicious network connections  
- Registry persistence **+** encoded PowerShell  
- Registry persistence **+** file creation in user-writable paths  
- Registry persistence **+** parent LOLBin (`mshta`, `rundll32`, `regsvr32`)  
- Registry persistence **+** credential file access (rare but critical)

**Correlate using:**
- `union` of `Process`, `File`, `Network`, and `Registry` events around the detection time.
- Look for “burst patterns” of execution within 2 minutes.

---

## 6.5 Lateral Expansion & Blast-Radius Mapping

**Objective:** Assess whether the persistence belongs to a single endpoint or a broader intrusion campaign.

**Queries:**
- Hunt for identical registry values across environment.
- Hunt for the same SHA256 across multiple hosts.
- Hunt for the same IP/domain in `DeviceNetworkEvents`.
- Verify whether the attacker moved laterally before persistence creation:
  - Look for `ADMIN$` writes  
  - NTLM/Kerberos authentication anomalies  
  - RDP/PsExec patterns  

**Recommended pivots:**
- `DeviceNetworkEvents | summarize by RemoteIP, DeviceName`
- `DeviceEvents | where ActionType == "ImageLoad"` for DLL hijacking
- `SigninLogs` for account compromise checkpoints

---

## 6.6 Remediation, Containment & Forensic Notes

**If confirmed malicious:**

1. **Isolate host immediately**
   - Prevent further credential theft, lateral movement, or persistence re-activation.

2. **Export the registry key**
   - Use:  
     `reg export <path> <output>.reg`
   - Store as evidence.

3. **Extract payload referenced by the registry key**
   - Preserve original timestamp and metadata.

4. **Reset credentials** for:
   - Local admin accounts
   - Domain accounts tied to initiating processes
   - Any high-value tier accounts

5. **Search for lateral spread**
   - Same SHA256  
   - Same persistence key pattern  
   - Same LOLBin invocation chain

6. **Remove persistence key**
   - Only after full forensic preservation.

7. **Harden registry permissions**
   - Validate ACLs for persistence-prone keys (`Run`, `RunOnce`, `Winlogon`, `AppInit_DLLs`).

8. **Initiate threat-intel feedback**
   - Feed IOCs (SHA256, URLs, domains) into your TI system for enrichment.

---

## 6.7 Key Pivots for IR & Threat Hunting Teams

| Pivot Type | Table | Field(s) | Purpose |
|------------|--------|----------|---------|
| **Parent Process Reconstruction** | DeviceProcessEvents | ProcessId, InitiatingProcessId | Follow process lineage |
| **Payload Creation** | DeviceFileEvents | FileName, SHA256, FolderPath | Validate if payload was staged |
| **Network Retrieval** | DeviceNetworkEvents | RemoteIP, RemoteUrl | Identify download → persistence chains |
| **Signed/Unsigned Checks** | DeviceFileCertificateInfo | IsTrusted, SignatureStatus | Confirm legitimacy |
| **Executable/DLL Prevalence** | FileProfile | GlobalPrevalence, LocalPrevalence | Determine rarity of binary |
| **Registry Tampering** | DeviceRegistryEvents | RegistryKey, ValueData | Root cause of persistence |
| **Account Compromise Indicators** | SigninLogs / IdentityInfo | UserPrincipalName | Determine if attacker used stolen credentials |

---

## 6.8 IOC Catalogue (Persistence-Focused)

| IOC Type | Examples |
|----------|----------|
| Suspicious Paths | `%APPDATA%\*.exe`, `C:\Users\Public\`, `%TEMP%\*.dll` |
| Encoded Commands | PowerShell `-EncodedCommand`, Base64 payloads |
| Known LOLBins | `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe` |
| Network Persistence | `http://malicious.site/payload.exe` |
| IFEO Debugger Keys | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*` |
| LSA Plugins | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\*` |
| COM Hijacks | `InProcServer32` pointing to AppData DLLs |
| Malicious Services | ImagePath to non-signed executables |

---

# End of Section 6–9 Consolidation

