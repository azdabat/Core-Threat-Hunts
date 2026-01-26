# Detection Engineering & Threat Hunting Framework  
**Author:** Ala Dabat -This is a framework and a methadology I myself have created from hard earned trial and error. </br>
**Version:** 2025  
**Scope:** Core Threat Hunts + Advanced Engineering Hunts  
**Platform:** Microsoft Sentinel • Microsoft Defender for Endpoint  
**Focus:** Behaviour-led detection, adversary modelling, IR workflow, risk scoring, MITRE coverage, sample data demonstration.

> [!IMPORTANT]
> **L3 Ecosystem Modeling vs. Operational Alerts**
>
> These rules represent **Complete Attack Chains (L3)** designed to model the full "Attack Ecosystem." They prioritize maximum visibility and context aggregation over alert volume constraints.
>
> **Operational Guidance:**
> * **Do not deploy these raw** into a high-volume production environment without tuning. These are POC and sources of attack methadologies and differenct attack ecosystems. They are NOT a finished product.
> * **Decomposition Required:** For standard L1/L2 threat hunting and detection engineering, these logical structures should be **decomposed**—stripping away complex engineering components to focus on a "Single Baseline Truth" with bounded context. "Splitting" the rule does not mean losing the big picture. We use Correlated Incidents in the SIEM to stitch these separate alerts together into a single Attack Story. The Detection Rule is the sensor; the Incident is the narrative.
>
> *For operational, production-ready hunting playbooks tailored for L2 analysts, please refer to my [Composite Threat Hunting Rules](https://github.com/azdabat/Composite-Threat-Hunting-Rules) repository. This is where the real work lives*

---

<p align="center">
  <b>“Intelligence-led detection engineering — converting adversary behaviour into measurable defensive depth.”</b>
</p>

---

## Cousin Rules & Attack Ecosystem Coverage

Part of this framework’s power is the **Cousin Rule Concept**:

> When a high−fidelity composite is created for one execution surface in an attack ecosystem, its *cousin* is the adjacent execution surface that shares the same adversary goal but lives in a different **noise domain**.  
> Cousin rules are **separate but paired** — they do not mix truth anchors with noisy signals that dilute fidelity.

### Definition

**Cousin Rules:**  
For any given detection composite, a cousin rule is the *paired counterpart* in the same attacker ecosystem that:

- Represents a **different execution/persistence surface**
- Shares the same **attack intent**
- Requires **stricter noise gating**
- Is structured as a **twin detection module**
- Improves **ecosystem coverage** without breaking rule fidelity

This table maps your composites to ecosystems and their cousins, with MITRE technique groupings.

---

## Ecosystem Table — Composites + Cousins (Roadmap)

| Ecosystem | Primary Composite | MITRE Technique | Cousin Composite (Planned/POC) | MITRE | Notes |
|-----------|------------------|------------------|-------------------------------|-------|-------|
| **Registry Persistence** | `Registry_Persistence_Background_Service_TaskCache` | T1543.003, T1053.005 | *Registry Persistence (Alternate Anchors)* | T1543, T1053 | e.g., HKEY_CLUSTER_SERVICE, COM task persistence |
| | `Registry_Persistence_Hijack_Interception` | T1546.* (IFEO/COM/AppInit) | *Registry Hijack Cousins* | T1546.* | e.g., Winlogon handler, shell open interception |
| | `Registry_Persistence_Userland_Autoruns` | T1547.001/014/004 | *Userland Autoruns Cousin* | T1547.* | e.g., Policies RunOnce, ActiveSetup deep variants |
| **Scheduled Task Execution** | *(covered by TaskCache + Registry pers.)* | T1053.005 | `ScheduledTask_Execution_TwinRule` | T1053.005 | svchost/taskeng based exec (no schtasks.exe) |
| **Service Execution** | `SMB_Service_Execution` | T1021.002 / T1543.003 | `Service_Exec_ScheduleTask_Cousin` | T1053.005 | svchost scheduler execution surface |
| **Lateral Movement** | `SMB_Service_Lateral` | T1021.002 | `WMI_RemoteExec_Cousin` | T1021.006 | remote process via WMI |
| |  |  | `WinRM_Exec_Cousin` | T1021.004 | PowerShell/WinRM lateral |
| **Execution (LOLBins/Proxy)** | `TrustedParent_LOLBin_InMemoryInjection_Chain` | T1218 / T1055 | `TaskExec_LOLBin_Injection_Cousin` | T1218/T1055 | LOLBin launched from Scheduled Task surface |
| **Credential Access** | *(existing rule needed)* | T1003 | `LSASS_Access_Cousin` | T1003.001 | DCSync / NTLM Harvest twin |
| **Identity Abuse (OAuth/Token)** | *(MITRE coverage from threat model SOP)* | T1621 / T1078.004 | `Identity_ConsentGrant_Cousin` | T1621 | Token replay vs lateral token misuse |
| **Persistence (File/Driver)** | *(POC/Research)* | T1547 / T1543 | `Driver_Persistence_Cousin` | T1543.008 | KMDF/Driver load surface |

---

## Framework Logic Behind Cousin Pairing

The cousin concept is not just “another rule.” It is based on these principles:

### 1. **Different Noise Domain**
Each cousin lives in a parallel surface that has a *different operational noise profile*.

Example:
- `services.exe` service exec rule — low noise → can be aggressive  
- `svchost.exe` scheduled task exec — high noise → needs strict anchors

Both cover lateral movement, but the host process and noise pattern differ.

---

### 2. **Separate Truth Anchors**
Never mix truth anchors across cousins.

Your Service rule anchors on:
```
services.exe spawning an uncommon child (baseline truth)
```
Your Scheduled Task cousin anchors on:
```
Explicit task create/exec signals
AND/OR Task XML drops/TaskCache registry writes
```

These are logically adjacent, but not the same anchor.

---

### 3. **Composite Isolation**
Coupling them in one rule breaks:
- noise suppression
- operational fidelity
- analyst clarity

Keeping them **separate maintains precision**.

---

### 4. **Ecosystem Continuity**
Every primary composite should answer four questions:

1. **What is the attack surface?**  
2. **What is the minimum truth anchor?**  
3. **What adjacent surfaces share intent?**  
4. **What cousin composites must exist to cover those surfaces?**

This ensures coverage without noise dilution.

---

##  Roadmap Example — From Primary to Cousin

###  Registry Persistence Ecosystem
- Primary: Background/Service/TaskCache writes  
- Cousin 1: Registry interception (IFEO/COM/AppInit)  
- Cousin 2: Extended run keys (Policies/Explorer/ActiveSetup)  
- Cousin 3: Shell/Handler persistence

###  Lateral Movement Ecosystem
- Primary: SMB service execution  
- Cousin 1: Scheduled Task execution  
- Cousin 2: WMI remote execution  
- Cousin 3: WinRM remote execution  
(*add based on telemetry available*)

###  Execution / Injection Ecosystem
- Primary: Trusted parent → LOLBin → injection  
- Cousin 1: Task-spawned LOLBin → injection  
- Cousin 2: PSExec/Impacket injection path

### Identity Ecosystem
- Primary: Consent grants (persistence)  
- Cousin 1: Token replay events  
- Cousin 2: Conditional Access bypass indicators

---

##  How to Use these Tables

When you build a composite rule:
1. Locate the ecosystem (e.g., Persistence, Lateral, Execution)
2. Identify primary rule anchor
3. Populate known cousins in the same ecosystem
4. For each cousin:
   - Define a distinct **Minimum Truth** anchor
   - Add **Reinforcement signals**
   - Enforce **Noise suppression**
   - Produce a **HunterDirective**
5. Test cousin rule in ADX / lab
6. Document in GitHub with screenshots

---

##  Why This Section Matters

- Avoids **unstructured rule proliferation**
- Ensures **systematic coverage**
- Helps you **plan a roadmap**
- Provides clarity for future reviewers
- Builds a **repeatable ecosystem matrix**

---

## How to Expand

You can later add columns for:

- Risk Score ranges  
- Known false positives suppressed  
- Required telemetry  
- Prevalence thresholds

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
   - Monolith brittle rules for composite deconstruction. 
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
