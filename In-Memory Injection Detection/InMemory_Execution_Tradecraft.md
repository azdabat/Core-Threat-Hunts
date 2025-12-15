# In-Memory Execution & Injection — Technical Synopsis

Author: Ala Dabat  
Scope: Endpoint Tradecraft & Detection Engineering  
Audience: SOC Analysts, Threat Hunters, Detection Engineers  

---

## Overview

Modern malware increasingly avoids writing malicious executables to disk.  
Instead, attackers execute **entirely in memory**, abusing legitimate Windows functionality to run malicious code inside trusted processes.

This class of tradecraft underpins:

- Ghost DLLs / DLL Hollowing  
- Reflective DLL loading  
- Process Hollowing  
- Fileless and semi-fileless loaders (Rust / Go / C++ implants)  

Because these techniques bypass traditional file-based detections, they represent one of the **hardest execution vectors to detect**.

The **Abnormal Process Tree Inheritance Hunt** directly targets this problem by focusing on the *mandatory system behaviors* these techniques cannot avoid.

---

## Why In-Memory Execution Works

Most AV and EDR controls historically focus on:

- File creation
- Executable hashes
- Process creation
- Known malicious binaries

In-memory techniques deliberately avoid all of these by:

- Never dropping a traditional executable to disk
- Reusing trusted, signed processes
- Executing payloads directly from memory regions

The result is malware that:
- Leaves minimal forensic artifacts
- Appears to be legitimate software at a glance
- Survives basic signature and IOC-based detection

---

## Core Principle Behind Detection

Although payloads never touch disk, **they must still interact with the Windows operating system** to execute.

All in-memory execution techniques ultimately rely on a **small, privileged set of low-level Windows memory APIs** to:

1. Allocate memory
2. Write code into that memory
3. Transfer execution to that memory

These steps cannot be skipped.

This invariant is what makes **behavioral detection possible**.

---

## How In-Memory Injection Techniques Work

### 1. Reflective DLL Loading

Reflective loading is the foundational technique for executing a malicious DLL without using `LoadLibrary`.

#### Execution Stages

| Stage | Name | Description |
|-----|------|-------------|
| Stage 1 | Staging | Malicious code (often a raw DLL) is downloaded or loaded as a byte array (memory or disk). |
| Stage 2 | Allocation | Memory is allocated inside a target process using APIs such as `VirtualAllocEx` or `NtAllocateVirtualMemory`. |
| Stage 3 | Writing | The raw DLL bytes are written into the allocated memory using `WriteProcessMemory`. |
| Stage 4 | Execution | Execution is transferred using `CreateRemoteThread` or `QueueUserAPC`. |

#### Result

- The DLL is never registered with the OS loader
- No normal DLL load events occur
- Execution happens entirely from memory

---

### 2. Ghost DLLs / DLL Hollowing

Ghost DLLs (also called DLL Hollowing or RunPE-in-memory) are an evolution of reflective loading.

The goal is **camouflage**.

#### How It Works

1. **Legitimate Mapping**  
   A legitimate, signed DLL (often from `System32`) is mapped into the target process.

2. **Ghosting / Patching**  
   The attacker overwrites the mapped memory section with malicious code using memory write APIs.

3. **Execution**  
   The process executes malicious instructions, but the memory region still appears to belong to a signed DLL.

#### Result

- Memory scanners see a *signed module*
- The executable code inside that module is malicious
- Traditional signature checks fail

This technique is heavily used in advanced post-exploitation frameworks.

---

### 3. Process Hollowing

Process Hollowing targets an entire executable rather than a DLL.

#### Execution Stages

| Stage | Description |
|------|-------------|
| Create Suspended | A legitimate process (e.g., `notepad.exe`) is launched in a suspended state. |
| Hollow | The original code section is unmapped or overwritten. |
| Inject | Malicious code is written into the hollowed memory region. |
| Resume | The process resumes execution, running attacker code under a benign process name. |

#### Result

- Process name and metadata appear legitimate
- The actual executed code is malicious
- On-disk file remains clean

---

## The Detection Challenge

From a detection perspective:

- No malicious file exists
- No suspicious executable is created
- Parent processes are trusted
- The payload is custom and polymorphic

**Static detection fails by design.**

---

## The Invariant: Mandatory Low-Level APIs

Despite their differences, **all in-memory techniques rely on the same core operations**:

### Mandatory API Categories

| Function | Purpose |
|--------|---------|
| `VirtualAllocEx` / `NtAllocateVirtualMemory` | Allocate executable memory |
| `WriteProcessMemory` | Insert malicious code |
| `CreateRemoteThread` / `QueueUserAPC` | Transfer execution |

In Microsoft Defender for Endpoint (MDE), these operations are surfaced as **behavioral `ActionType` events**, not raw API names.

---

## Why the Abnormal Process Tree Inheritance Hunt Works

The hunt does **not** attempt to detect malware code.

Instead, it detects the **delivery mechanism and execution behavior**:

1. A trusted user-facing application spawns a LOLBin  
2. The LOLBin performs memory-manipulation behaviors  
3. Optional confirmation via suspicious image loads or rapid network beacons  

This chain is:
- Extremely rare in benign software
- Mandatory for in-memory attacks
- High-confidence when correlated

---

## Detection Philosophy

| Traditional Detection | This Approach |
|----------------------|---------------|
| Hashes & signatures | Behavioral invariants |
| File artifacts | Memory behavior |
| Known malware | Unknown / custom loaders |
| Single events | Correlated execution chains |

This is why the hunt remains effective against:
- Ghost DLLs
- Reflective loaders
- Rust / Go implants
- Red-team frameworks
- Novel malware families

---

## Relationship to MITRE ATT&CK

These techniques map directly to well-documented ATT&CK behaviors:

| Tactic | Technique | ID |
|------|----------|----|
| Execution | Signed Binary Proxy Execution | T1218 |
| Execution | User Execution | TA0002 |
| Defense Evasion | Reflective Code Loading | T1620 |
| Defense Evasion | Process Injection | T1055 |
| Command & Control | Application Layer Protocol | T1071 |
| Command & Control | Ingress Tool Transfer | T1105 |

The hunt detects the **intersection of these techniques**, not isolated indicators.

---

## Key Takeaway

> In-memory malware is not invisible — it is *behaviorally constrained*.

Attackers can:
- Hide files  
- Obfuscate payloads  
- Evade signatures  

They **cannot** avoid:
- Abnormal process inheritance  
- Memory manipulation behaviors  
- Execution transfer into allocated memory  

This invariant is what makes advanced behavioral detection possible.

---

## Recommended Companion Material

To fully understand and operationalize this detection, review:

- Abnormal Process Tree Inheritance Hunt (KQL)
- Capability-Aware Execution Risk Engine
- Registry & Startup Persistence Drift Hunts
- Scheduled Task Re-Registration Detection

Together, these detections form a comprehensive post-exploitation coverage strategy.
