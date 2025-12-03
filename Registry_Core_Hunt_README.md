# Advanced Registry Persistence Detection (KQL)
High-fidelity detection logic for malicious registry-based persistence, execution hijacking, and defense evasion.  
This rule uses **multi-signal scoring**, **prevalence analysis**, **trusted signer validation**, **LOLBin detection**,  
and **content inspection** to isolate real attacks with minimal false positives.

---

##  What This Rule *Will* Detect

| Category | Example Techniques / Indicators | Why It Triggers |
|---------|---------------------------------|-----------------|
| **Run / RunOnce Persistence** | Malware loaders, RATs, droppers in HKLM/HKCU Run keys | Suspicious paths, rare binaries, unsigned processes |
| **PowerShell/Encoded Payloads** | `-EncodedCommand`, `IEX(`, Base64 blobs | Scripted stagers, CS/Empire/Covenant payloads |
| **LOLBAS Persistence Abuse** | `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin` | BadStrings + suspicious extensions |
| **Active Setup Hijacks** | Emotet, Qakbot, FIN7 loaders | Unusual CLSID/Installed Components manipulation |
| **Winlogon Shell/Userinit Hijacking** | Credential theft loaders, ransomware loaders | Critical persistence keys modified |
| **AppInit_DLLs Abuse** | DLL hijacks, credential stealers | User-writable DLL references or unsigned DLLs |
| **Service Persistence / ImagePath Tampering** | Malicious Windows services, DLL hijacks | HKLM\SYSTEM\CCS\Services manipulations |
| **IFEO Hijacking** | Mimikatz, Emotet, TrickBot, custom implants | Debugger redirection on arbitrary binaries |
| **COM Hijacking (InProcServer32)** | FIN7, Turla, APT29 | Suspicious DLL/EXE paths in CLSID entries |
| **LSA Plugin Injection** | Credential dumping SSP modules | HKLM\SYSTEM\CCS\Control\Lsa modifications |
| **User-writable Execution Paths** | AppData/Public/Temp persistence | `PointsToUserWritable` flag + rare binaries |
| **Network-enabled Persistence** | URLs, domains, IPs inside registry | C2-linked persistence with exfil indicators |
| **Rare Executables / Unknown Binaries** | Custom RATs, red-team payloads | Prevalence score ≤ 2 devices |

---

##  What This Rule *Will NOT* Detect

| Missed Category | Description | Why It's Not Covered |
|-----------------|-------------|----------------------|
| **Fileless / Memory Persistence** | Reflective DLLs, in-memory beacons | No registry footprint |
| **WMI Event Consumers** | FilterToConsumerBindings, CommandLineEventConsumer | Requires `WMIEvent` tables (paired rule provided below) |
| **Scheduled Tasks Persistence** | `schtasks.exe`, TaskCache registry | Needs `DeviceProcessEvents` + TaskCache rule |
| **Startup Folder Entries** | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*` | No registry key touched |
| **Services installed via MSI** | Legitimate enterprise apps installing services | Usually signed + trusted publisher |
| **Browser Extension Persistence** | Chrome/Edge extension loading | Different telemetry surface |
| **Kernel/Driver Persistence** | Malicious drivers, tampered drivers, rootkits | Requires MDE driver events / ELAM |
| **GPO-based persistence** | Group Policy Preferences XML / Registry.pol | Not written by processes on endpoint |
| **Autoruns locations not registry-based** | Winlogon notifications, ShimDB, Sidebar Gadgets | Not covered in registry set |

---

#  Hunting Directives (SOC Analyst Guide)

```markdown
###  Hunting Directives

1. **Validate the initiating process**
   - Check signer, company, path, and hash rarity.
   - Unsigned or unknown binaries in registry persistence = HIGH confidence malicious.

2. **Review the ValueData**
   - Look for executables/scripts in `AppData`, `ProgramData`, `Temp`, `Public`.
   - Check for encoded PowerShell, URLs, domains, or IP addresses.

3. **Check for LOLBAS behaviour**
   - `rundll32`, `regsvr32`, `certutil`, `mshta`, `bitsadmin`, `curl`.

4. **Investigate privileged persistence keys**
   - Winlogon Shell/Userinit
   - AppInit_DLLs
   - LSA plugins
   - Services ImagePath tampering
   - IFEO Debugger redirection
   - COM hijacks (InProcServer32)

5. **Correlate with process execution**
   - Look for suspicious process trees around the same timestamp.

6. **Correlate with network signals**
   - Any registry persistence referencing URLs/IPs/domains is high-confidence malware.

7. **If persistence is malicious**
   - Isolate device
   - Dump registry key for evidence
   - Extract referenced payloads
   - Check for lateral movement or credential theft

8. **Feed confirmed IOCs into MISP / TI pipeline**
   - Improve future scoring for similar TTPs.

### MITRE ATT&CK Coverage Heatmap

| Tactic | Techniques |
|--------|------------|
| **TA0002 – Execution** | T1059 (PowerShell), T1218 (LOLBAS), T1047 (WMI exec if chained) |
| **TA0003 – Persistence** | T1547.001 (Registry Run Keys), T1547.009 (LSA), T1546.012 (IFEO), T1546.015 (COM Hijacking), T1543.003 (Services), T1546 (Event-triggered) |
| **TA0004 – Privilege Escalation** | T1546 (Hijacking), T1543 (Services), credential provider modifications |
| **TA0005 – Defense Evasion** | T1218 (LOLBAS), encoded payloads, hidden locations, unsigned executables |
| **TA0006 – Credential Access** | T1556 (LSA plugins), T1003 (credential reading via hijacks) |
| **TA0011 – Command & Control** | T1105 (Ingress Tool Transfer via persistence key URL/IP reference) |

