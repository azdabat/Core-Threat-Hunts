# WMI ATTACK ECOSYSTEM — DETECTION ARCHITECTURE & THREAT MODEL (L2.5 / L3)

Author: Ala Dabat  
Scope: Windows Management Instrumentation (WMI) abuse across execution, lateral movement, persistence, defense evasion, and **process-less fileless tradecraft**  
Audience: Senior SOC Analysts, Threat Hunters, Detection Engineers  
Philosophy: **Attack-chain fidelity over event noise**

---

## 1. Executive Summary

This repository documents the **complete WMI attack ecosystem** as observed in real-world APT and financially motivated campaigns, and explains **why WMI detection must be architected as a fleet of specialized rules**, not a single “god rule”.

The work deliberately separates:

- **Process-based WMI abuse** (where attackers spawn processes)
- **Process-less / fileless WMI abuse** (where attackers execute entirely inside `scrcons.exe`)
- **Source (attacker) behavior vs Target (victim) effects**
- **Heavy telemetry (DLL loads, registry)** vs **light telemetry (process/network)**

This design reflects how modern adversaries actually operate — and how production SOCs survive noise.

---

## 2. Why WMI Matters to Attackers

WMI is attractive because it is:

- Native to Windows (LOLBAS)
- Privileged by default in enterprise environments
- Scriptable (VBScript / JScript / PowerShell / COM)
- Capable of **remote execution**, **persistence**, and **fileless execution**
- Poorly monitored beyond basic process creation

Threat actors use WMI to:
- Recon systems quietly
- Execute payloads remotely
- Persist without files
- Evade EDR process-based detections
- Blend with legitimate IT automation

---

## 3. The WMI Attack Ecosystem (High-Level)

Recon → Remote Execution → Victim Execution → Persistence → Defense Evasion

↘ Process-less Execution (Blind Spot)


This ecosystem breaks into **two fundamentally different execution models**:

1. **Process-Chaining WMI**  
   (spawns child processes → visible via process telemetry)

2. **Process-Less WMI (ActiveScriptEventConsumer)**  
   (executes entirely inside `scrcons.exe` → invisible to 4688 logic)

Trying to detect both with a single rule **fails**.

---

## 4. Rule Architecture (Why We Split the Rules)

### Engineering Principles Applied

| Principle | Why It Matters |
|--------|----------------|
| Separate execution models | Process-less attacks break child-process logic |
| Separate heavy telemetry | Image load + registry tables are expensive |
| Separate tuning domains | Legacy SCCM ≠ workstation behavior |
| Score chains, not events | Prevents alert fatigue |
| Distinct attacker vs victim views | Lateral movement splits hosts |

### Resulting Rule Fleet

| Rule | Purpose |
|---|---|
| **Rule A — WMI Chained Attack Hunt** | Process-based WMI execution & persistence |
| **Rule B — WMI Fileless Persistence Hunt** | ActiveScriptEventConsumer / process-less abuse |

Each rule is **quiet by itself**, but **complete together**.

---

## 5. Rule A — WMI CHAINED ATTACKS (Process-Based)

### What This Rule Detects

This rule models **classic WMI abuse chains** where execution results in **observable process activity**.

### Core Attack Chain

1. **Recon**
   - `wmic process get`
   - `wmic qfe get`
   - `Get-WmiObject` / `Get-CimInstance`

2. **Remote Execution (Source Host)**
   - `wmic /node:TARGET process call create`
   - `Invoke-WmiMethod Win32_Process Create`

3. **Victim-Side Execution**
   - `wmiprvse.exe` spawns `cmd.exe`, `powershell.exe`, `mshta.exe`, etc.

4. **Persistence (Optional)**
   - WMI Event Subscriptions that spawn processes

5. **Defense Evasion (Optional)**
   - Shadow copy deletion
   - Service stopping via WMI

### Why This Is a Separate Rule

- Relies on **process creation telemetry**
- Cleanly models **attacker vs victim** hosts
- High confidence when child processes exist
- Low false positives when scored correctly

---

### MITRE Mapping — Rule A

| Stage | MITRE Technique |
|---|---|
| Recon | T1047, T1082 |
| Remote Execution | T1047, T1021.002 |
| Victim Execution | T1059 |
| Persistence | T1546.003 |
| Defense Evasion | T1562, T1070 |

---

### What Rule A WILL Catch

| Tradecraft | Covered | Why |
|---|---|---|
| WMIC remote execution | ✅ | `/node:` + process creation |
| PowerShell WMI execution | ✅ | CIM/WMI method calls |
| WMI persistence spawning PowerShell | ✅ | Child process visibility |
| Ransomware staging via WMI | ✅ | Process + defense evasion |

### What Rule A WILL NOT Catch

| Tradecraft | Not Covered | Reason |
|---|---|---|
| ActiveScriptEventConsumer fileless execution | ❌ | No child process |
| In-memory script execution inside scrcons | ❌ | Process-less |
| Registry-only C2 inside WMI | ❌ | No process or network |

That gap is intentional — and addressed by Rule B.

---

## 6. Rule B — WMI FILELESS / PROCESS-LESS PERSISTENCE

### The Blind Spot This Rule Fixes

**ActiveScriptEventConsumer** allows VBScript/JScript to execute **inside `scrcons.exe -Embedding`**.

Key properties:
- No `cmd.exe`
- No `powershell.exe`
- No 4688 event
- Logic runs via COM objects
- Can perform registry I/O and network I/O entirely in memory

Most SOCs **do not see this at all**.

---

### How the Attack Works (Internals)

1. Attacker creates:
   - `__EventFilter`
   - `ActiveScriptEventConsumer`
   - `__FilterToConsumerBinding`

2. Script is stored:
   - In WMI repository (OBJECTS.DATA)
   - Not in a file

3. On trigger:
   - `scrcons.exe -Embedding` loads:
     - `vbscript.dll`
     - `jscript.dll`
     - `scrobj.dll`

4. Script executes in memory:
   - Registry reads/writes
   - Network requests (XMLHTTP / WinHttp)
   - No child processes required

---

### Why This Required a Separate Rule

| Reason | Explanation |
|---|---|
| Performance | DLL load tables are massive |
| Logic | No child process chain |
| Tuning | Legacy scripting environments vary |
| Accuracy | Requires substrate-based detection |

This rule detects **capability**, not payload.

---

### Detection Philosophy — Rule B

We detect the **minimum conditions required for fileless execution**:

1. **Substrate**
   - `scrcons.exe` loading script engine DLLs

2. **Runtime**
   - `scrcons.exe -Embedding`

3. **High-Fidelity Enhancers**
   - Network from `scrcons.exe`
   - WBEM/CIMOM registry modification

We score **distinct signals**, not event volume, to avoid SCCM noise.

---

### MITRE Mapping — Rule B

| Component | MITRE Technique |
|---|---|
| WMI Persistence | T1546.003 |
| Script Execution | T1059.005 / T1059.007 |
| Registry Interaction | T1112 |
| Network C2 | T1071.001 |
| Defense Evasion | T1027 |

---

### What Rule B WILL Catch

| Tradecraft | Covered | Why |
|---|---|---|
| ActiveScriptEventConsumer persistence | ✅ | Substrate + runtime |
| Fileless VBScript/JScript execution | ✅ | DLL load detection |
| Registry-based C2 | ⚠️ | Heuristic, tuneable |
| scrcons.exe network C2 | ✅ | Rare, high signal |
| Obfuscated in-memory scripts | ✅ | Obfuscation doesn’t avoid DLLs |

### What Rule B WILL NOT Catch

| Tradecraft | Not Covered | Reason |
|---|---|---|
| Pure logic with no observable side-effects | ❌ | Telemetry limits |
| Non-script WMI consumers only | ❌ | Different substrate |
| Child-process-based WMI | ❌ | Covered by Rule A |

---

## 7. Why This Architecture Is “L3”

This ecosystem design demonstrates:

- **Threat modeling over syntax**
- **Detection architecture awareness**
- **Performance-conscious telemetry use**
- **Noise-resistant scoring**
- **Clear analyst actionability**

Instead of one fragile rule:
- We built **two precision tools**
- Each optimized for a different adversary behavior
- Together providing full WMI coverage

---

## 8. Analyst Mental Model (How to Use This in Practice)

1. **Rule A fires**
   - You are looking at **active execution or lateral movement**
   - Prioritize victim host isolation

2. **Rule B fires**
   - You are looking at **stealthy persistence or fileless C2**
   - Prioritize subscription inspection and forensic validation

3. **Both fire in proximity**
   - You are looking at a **complete WMI compromise lifecycle**
   - Escalate immediately

---

## 9. Final Takeaway

WMI is not “one technique”.  
It is an **ecosystem**.

You cannot defend it with:
- a single alert,
- a single table,
- or a single mental model.

This repository documents **how to think about WMI the way attackers do**, and how to build detections that survive real enterprise environments — quietly, accurately, and defensibly.

This is the difference between **writing detections** and **owning detection architecture**.


