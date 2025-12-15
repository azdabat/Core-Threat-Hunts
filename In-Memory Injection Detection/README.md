# Capability-Aware Abnormal Execution & In-Memory Injection Detection

Author: Ala Dabat  
Detection Class: Advanced Endpoint Threat Hunting (MDE / Sentinel)  
Audience: SOC L3, Threat Hunters, Detection Engineers  

---

## Overview

This detection focuses on **modern, fileless and semi-fileless execution techniques** used by advanced attackers to evade traditional antivirus and signature-based EDR detections.

Rather than dropping obvious malware to disk, attackers increasingly rely on:

- **Trusted parent processes** (Office, browsers, collaboration tools)
- **Living-Off-the-Land Binaries (LOLBins)** for execution
- **In-memory loaders and injection** (Ghost DLLs, reflective loading)
- **Rapid outbound beacons** for staging and command-and-control

This rule is designed to detect **the behavior of the attack chain**, not a specific malware family.

---

## The Core Problem This Detection Solves

Traditional detections fail when:

- No malicious file is written to disk
- The parent process is trusted and signed
- The payload is injected directly into memory
- The loader is custom (Rust / Go / C++)
- The attacker uses LOLBins as execution glue

In these scenarios:
- Hash-based detection fails
- Static signatures fail
- IOC-based rules fail

**Behavioral correlation is required.**

---

## High-Level Attack Explanation (Plain English)

### What an attacker does

1. A user opens a document, clicks a link, or runs a trusted application  
2. That trusted application launches a built-in Windows tool (LOLBin)  
3. The LOLBin loads or injects malicious code **directly into memory**  
4. No obvious malware file exists on disk  
5. The injected code establishes outbound communication (C2 or staging)

The system looks “clean” — but it is compromised.

---

## What Is an “Abnormal Process Tree”?

 # In a normal system:

explorer.exe → chrome.exe
explorer.exe → winword.exe


# In an abnormal execution chain:

winword.exe → powershell.exe
chrome.exe → mshta.exe
teams.exe → rundll32.exe


These relationships are **not common in normal business workflows**, especially when followed by low-level behavior.

---

## What Is a “Ghost DLL” / In-Memory Load?

A Ghost DLL is a library that is:

- Loaded reflectively or mapped into memory
- Often unsigned or untrusted
- Loaded from a user-writable path
- Sometimes never written to disk at all

These techniques are commonly used by:
- Red-team frameworks
- Post-exploitation toolkits
- APT loaders
- Custom Rust/Go implants

---

## Detection Strategy (Capability-Aware)

This detection uses **layered behavioral evidence** and adapts automatically to the tenant’s telemetry capabilities.

### Core Signals

| Signal | Description |
|-----|-------------|
| Abnormal process tree | Trusted parent spawning a LOLBin |
| Injection behavior | Cross-process memory tampering (if available) |
| Ghost DLL load | Unsigned module loaded from writable path |
| Network beacon | Outbound connection shortly after execution |

### Graceful Degradation

Not all environments expose the same telemetry.

This detection:
- **Confirms injection** when injection ActionTypes are available
- **Falls back to image-load anomalies** when injection telemetry is missing
- **Falls back to beacon correlation** when memory telemetry is sparse
- **Never silently fails**

Severity and analyst guidance adapt accordingly.

---

## Full MITRE ATT&CK Mapping (Attack Chain)

| Attack Phase | Technique | ID |
|------------|----------|----|
| Initial Execution | User Execution | TA0002 |
| LOLBin Abuse | Signed Binary Proxy Execution | T1218 |
| In-Memory Loading | Reflective Code Loading | T1620 |
| Process Injection | Process Injection | T1055 |
| Defense Evasion | Obfuscated / Fileless Execution | TA0005 |
| Command & Control | Application Layer Protocol | T1071 |
| Payload Ingress | Ingress Tool Transfer | T1105 |

This detection does **not** rely on any single technique — it models the chain.

---

## What This Detection Will Catch

- Ghost DLL loaders
- Reflective DLL injection
- LOLBin-based in-memory loaders
- Rust / Go staged payloads
- Red-team frameworks using PowerShell glue
- Fileless post-exploitation implants

---

## What This Detection Will NOT Catch

- Kernel-only malware
- Hypervisor-assisted implants
- Attacks that never spawn a LOLBin
- Attacks entirely contained within a single trusted process

These require kernel telemetry or memory scanning.

---

## SOC Analyst SOP (Standard Operating Procedure)

### When Severity = CRITICAL

1. Isolate the host immediately
2. Capture memory if possible
3. Identify injected target process
4. Review spawned child processes
5. Pivot on outbound connections
6. Reset affected user credentials
7. Consider full reimage

### When Severity = HIGH

1. Validate parent → LOLBin relationship
2. Review loaded modules and signatures
3. Enrich outbound connections with TI
4. Hunt for persistence mechanisms
5. Escalate if additional signals appear

### When Severity = MEDIUM

1. Validate business justification
2. Confirm user intent
3. Monitor for follow-on behaviors
4. Baseline if legitimate

---

## Why This Detection Is Valuable

- Detects **real attacker behavior**, not indicators
- Resilient to evasion and polymorphism
- Works across mixed estates
- Suitable for proactive threat hunting
- Demonstrates advanced detection engineering capability

---

## Recommended Pairing

For complete coverage, pair this detection with:

- Registry persistence drift & rewrite hunts
- Startup folder persistence hunts
- Scheduled task re-registration hunts
- DLL and driver sideloading detection
- OAuth / cloud persistence detection

Together, these form a **full post-compromise detection framework**.
