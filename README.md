# Detection Engineering & Threat Hunting Framework  
**Author:** Ala Dabat  
**Version:** 2025  
**Scope:** Core Threat Hunts + Advanced Engineering Hunts  
**Platform:** Microsoft Sentinel • Microsoft Defender for Endpoint  
**Focus:** Behaviour-led detection, adversary modelling, IR workflow, risk scoring, MITRE coverage, sample data demonstration.

---

<p align="center">
  <b>“Intelligence-led detection engineering — converting adversary behaviour into measurable defensive depth.”</b>
</p>

---

# 1. Overview

This repository contains two layers of detection logic:

1. **Core Threat Hunts (Low Noise, High Signal)**  
   - Lightweight behavioural hunts  
   - Zero reliance on external TI feeds  
   - Daily/weekly SOC-ready investigations  
   - Generic TTP coverage (NTDS, SMB Lateral Movement, Rogue Devices, OAuth Abuse, RMM Abuse, Pipe C2, etc.)

2. **Advanced Detection Engineering Pack**  
   - High-fidelity correlation rules  
   - Scoring engines, kill chain classification  
   - MITRE-aligned, enriched, multi-signal analytics  
   - For L2/L3 SOC and IR teams  

Both follow the same **structured methodology**, shown below.

---

# 2. Detection Engineering Methodology

```
+---------------------------------------------------------------+
| 1. Threat Modelling                                          |
|    - Understand attacker TTPs                                |
|    - Map to MITRE ATT&CK                                     |
|    - Identify behavioural surfaces                           |
+---------------------------------------------------------------+
| 2. Telemetry Pivoting                                        |
|    - Map behaviours to tables (Process, File, Network, Auth) |
|    - Identify pivot keys (DeviceId, Account, SHA256, IP)     |
+---------------------------------------------------------------+
| 3. Behavioural Signal Extraction                             |
|    - Command-line patterns                                   |
|    - Share access, driver loads, registry writes             |
|    - Rare parent/child chains                                |
+---------------------------------------------------------------+
| 4. Scoring & Confidence Model                                |
|    - Prevalence scoring                                      |
|    - Kill chain stage mapping                                |
|    - Host rarity / unsigned / LOLBin scoring                 |
+---------------------------------------------------------------+
| 5. Correlation                                               |
|    - Multi-table JOINs                                       |
|    - Time-window correlation                                 |
|    - Enrichment: device, identity, service info              |
+---------------------------------------------------------------+
| 6. Output & Analyst Directives                               |
|    - Human-readable triage guidance                          |
|    - Next steps (IR workflow)                                |
|    - Blast radius queries                                    |
+---------------------------------------------------------------+
| 7. Pressure Testing                                          |
|    - Noise simulation                                        |
|    - Malicious dataset injection                             |
|    - Analyst-facing tables                                   |
+---------------------------------------------------------------+
```

---

# 3. Telemetry Coverage Map

| Behaviour Surface | Tables Used |
|-------------------|-------------|
| Process Activity | `DeviceProcessEvents` |
| File Writes / Drops | `DeviceFileEvents` |
| Driver Loads | `DeviceEvents` (DriverLoad) |
| Network Activity | `DeviceNetworkEvents` |
| Logons & Identity | `SigninLogs`, `DeviceLogonEvents` |
| Registry Writes | `DeviceRegistryEvents` |
| Configuration / EDR State | `DeviceInfo`, `DeviceTvmSecureConfigurationAssessment` |

---

# 4. MITRE ATT&CK Master Coverage Table (Examples)

| Tactic | Technique | What We Hunt |
|--------|-----------|--------------|
| **TA0001 Initial Access** | Spearphishing, OAuth Consent Abuse | Suspicious OAuth grant hunts |
| **TA0002 Execution** | PowerShell, LOLBins | Registry persistence, WSL, RMM abuse |
| **TA0003 Persistence** | Run Keys, LSA, AppInit_DLLs, IFEO | Registry Persistence Hunts |
| **TA0004 Privilege Escalation** | Driver abuse, NTDS extraction, WSL root shells | NTDS Hunt, WSL Hunt, LOLDrivers Hunt |
| **TA0005 Defense Evasion** | Masquerading, signed abuse | Prevalence scoring, signature checks |
| **TA0006 Credential Access** | NTDS.dit, DCSync, SSP injection | NTDS Core Hunt |
| **TA0007 Discovery** | AD Recon, host enumeration | AD Command Recon Hunt |
| **TA0008 Lateral Movement** | SMB Admin$, RDP abuse, Pipes | SMB Lateral Movement Hunt, Named Pipe Hunt |
| **TA0010 Exfiltration** | SMB, reverse shells, NTDS copy | NTDS and WSL exfil paths |
| **TA0011 Command & Control** | Named pipes, outbound IPs | Pipe C2 Hunt, Malicious IP Hunt |

---

# 5. Sample Core Hunt Outputs (Demonstration)

Below are **representative outputs** from pressure-tested rules.  
These tables are examples of what analysts will see.

---

## Example A — Rogue / Unmanaged Device Detection (Core Hunt)

**Simulated enterprise noise:**  
- 250 managed devices  
- 17 misnamed devices  
- 3 fully rogue devices  

**Final Hunt Output:**

| DeviceName | Onboarded | In MDE | NameOk | HasEdrIssues | RiskScore | Directive |
|------------|-----------|--------|--------|--------------|-----------|-----------|
| **ACME-LAP99X** | No | No | No | Yes | **11** | CRITICAL: Not onboarded + rogue hostname |
| **OFFICE-PRN01** | No | No | No | No | **9** | HIGH: Not in inventory |
| **HR-WSUS1** | Yes | Yes | No | Yes | **8** | HIGH: Non-standard name + EDR issues |

---

## Example B — NTDS Core Hunt (Behaviour-Only)

**Simulated malicious activity:**  
- secretsdump.py  
- ntdsutil shadow copy  
- NTDS staging in `C:\Users\Public\ntds.dit`  

| DeviceName | Indicator | Path / Command | Severity | Directive |
|------------|-----------|----------------|----------|-----------|
| **DC-01** | File Access | C:\Windows\NTDS\ntds.dit | HIGH | Investigate shadow copy / DCSync |
| **IT-ADMIN1** | Process | python.exe secretsdump.py dc01 | CRITICAL | Credential dump attempt |

---

## Example C — Malicious Outbound IP Behaviour (Core Hunt)

| DeviceName | RemoteIP | Prevalence | Geo | Severity | Directive |
|------------|----------|------------|-----|----------|-----------|
| **FINANCE-LAP12** | 185.220.101.65 | 1/250 | NL | HIGH | Check for C2 activity |
| **ACME-SQL02** | 139.60.161.99 | 1/250 | DE | HIGH | Investigate payload downloads |

---

## Example D — WSL Privilege Escalation Hunt

| DeviceName | CommandLine | Flags | Score | Directive |
|------------|-------------|--------|--------|-----------|
| **DEVOPS-LINUX01** | `wsl.exe --system bash -c "cat /etc/shadow"` | `--system` | 85 | Immediate review: Credential file access |
| **ACME-LAP22** | `mshta.exe -> wsl.exe bash -c curl attacker` | Parent=mshta | 95 | Likely host escape attempt |

---

# 6. Pivot Catalogue (IR Investigation Helpers)

| Pivot Goal | Query Surface | How to Use |
|------------|---------------|------------|
| Identify same SHA256 across estate | DeviceProcessEvents | `where SHA256 == "<hash>"` |
| Find all devices contacting same C2 | DeviceNetworkEvents | `where RemoteIP == "<ip>"` |
| Reconstruct process tree | DeviceProcessEvents | Filter by `ProcessId` + `InitiatingProcessId` |
| Enumerate all NTDS attempts | DeviceFileEvents + ProcessEvents | Search for "ntds", "shadow" |
| Track rogue hostname | DeviceInfo | Search AD object + DHCP leases |
| Confirm persistence payload | DeviceRegistryEvents | Inspect ValueData, path, signer |

---

# 7. Sample Attack Flow Demonstration

### Example: NTDS.dit Theft → Lateral Movement → Exfil

```
Attacker executes python secretsdump.py →  
Dumps NTDS.dit via shadow copy →  
Stages file in Public folder →  
Sends over SMB or HTTP to remote C2 →  
Attempts admin$ access on lateral hosts  
```

**Our hunts that trigger:**

- **NTDS Core Hunt**  
- **SMB Lateral Movement Hunt**  
- **Malicious IP Outbound Hunt**  
- **Rogue Device Hunt** (if lateral box is unmanaged)

---

# 8. Triage Workflow (Universal for All Hunts)

```
1. Confirm event legitimacy
   - Review parent process, signer, and user.

2. Identify intent
   - Persistence? Exfil? Priv Esc? Lateral movement?

3. Scope blast radius
   - Query for related IPs, hashes, users, devices.

4. Check correlated behaviours
   - File + network + process within same window.

5. Validate device integrity
   - EDR coverage, patch state, unusual hostname.

6. Respond
   - Isolate device
   - Reset credentials
   - Remove persistence
   - Extract evidence

7. Document findings
   - IOC list
   - Kill chain stage
   - Affected assets
```

---

# 9. Repository Contents

| Category | Description |
|----------|-------------|
| **/core-hunts/** | Lightweight behaviour-only hunts for L1/L2 SOC |
| **/engineering/** | Advanced correlation rules for L2/L3 & IR |
| **/matrices/** | MITRE mapping tables, cheat sheets |
| **/samples/** | Sample event datasets used for pressure-testing |
| **/docs/** | Methodology, IR workflow, detection philosophy |

---

# 10. Philosophy of This Repository

1. **Behaviour before signatures**  
2. **Correlation before alerts**  
3. **Context over noise**  
4. **Human-readable triage**  
5. **Enterprise-relevant attack paths**  
6. **Engineering-level depth, hunter-level agility**

This repository is intentionally built to reflect the real workflows of **modern detection engineering**, **SOC operations**, and **incident response**, while remaining readable and maintainable for hiring managers, SOC analysts, and threat hunters.

---

# END OF README
