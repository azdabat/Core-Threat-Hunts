# OAuth Threat Hunting Pack (L1/L2 Core Hunts)
### Author: Ala Dabat  
### Version: 2025-12  
### Repository Section: Core Threat Hunting → OAuth Detection Suite

---

# Overview

This pack contains **four core OAuth-focused hunts** designed for **L1 and L2 SOC analysts**. These hunts are intentionally:

- Easy to read  
- Operable by junior analysts  
- Built on simple, explainable scoring  
- Focused on **persistence**, **illicit consent**, **burst phishing patterns**, **token theft**, and **service principal backdooring**

Each hunt includes:

- Purpose & Threat Model  
- Full MITRE ATT&CK Mapping  
- Sample IOCs & IOAs  
- Analyst SOP / IR workflow  
- Detection logic summary  
- Full KQL detection query  

These hunts act as the **frontline OAuth detection suite** before escalating to L3/L4 analytics.

---

# TABLE OF CONTENTS

1. [Hunt 1 — Advanced OAuth Consent Risk Analysis (L1/L2 Core)](#hunt1)  
2. [Hunt 2 — OAuth Token Theft / Stolen Token Replay](#hunt2)  
3. [Hunt 3 — OAuth Burst Phishing Pattern Detection](#hunt3)  
4. [Hunt 4 — Service Principal Backdoor Detection (SP Credential Injection)](#hunt4)  
5. [MITRE ATT&CK Mapping](#mitre)  
6. [Incident Response Framework (SOC SOP)](#sop)  
7. [IOCs, IOAs, Malicious Behaviours Reference](#ioc)  

---

<a name="hunt1"></a>

# 1. Hunt 1 — Advanced OAuth Consent Risk Analysis (Scopes + Admin + Burst)

### Purpose  
Detect new **illicit consent grants** by evaluating risk of scopes, publisher reputation, admin-level consent, and early burst patterns.

### Threat Model  
Attackers regularly use OAuth apps for persistence:

- Phishing links lead users to malicious consent screens  
- Apps request **Mail.Read**, **Files.ReadWrite.All**, **Directory.ReadWrite.All**  
- Attackers gain long-term access even without passwords or MFA bypass  
- Admins granting high-value roles massively increase blast radius  

### What This Hunt Detects

| Attack Type | Detected? | Notes |
|------------|-----------|-------|
| Illicit user consent (Mail/File/Directory scopes) | ✔ | Core purpose of rule |
| Admin consent abuse | ✔ | Strong scoring weight |
| Burst phishing consent (multiple victims) | ✔ | L1/L2-friendly indicator |
| SaaS application onboarding | ✔⚠ | Benign but appears similar to phish |
| Token theft / replay | ✖ | Requires Hunt 2 |
| SP credential backdoors | ✖ | Requires Hunt 4 |

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| **T1078** — Valid Accounts | OAuth tokens act as credentials |
| **T1550.001** — Use of Stolen Tokens | Consent grants enable long-term access |
| **T1098** — Account Manipulation | OAuth permission assignments |
| **T1548** — Abuse Elevation Control Mechanisms | Admin-level consent |
| **T1566.002** — OAuth Phishing | Classic consent phishing patterns |

---

## IOAs / Behaviour Flags

- Unexpected consent to apps requesting `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`
- Publisher not in known safe orgs
- Multiple users consenting to same app in short time
- Unusual user agents during consent (curl, python, node libraries)
- Consent followed quickly by Graph API usage

## IOCs (Examples)

| IOC Type | Example |
|----------|---------|
| Malicious App Name | “AI Productivity Enhancer” |
| AppID | `6d1b4735-3c1d-4e8d-a128-98d5fd1e33d1` |
| Publisher | “Global Cloud Sync LLC” |
| Scope Indicators | `Mail.Read`, `Files.ReadWrite.All` |

---

## FULL KQL QUERY — Hunt 1  
### *Advanced OAuth Consent Risk Hunt (L1/L2 Core)*

```kusto
// Advanced Hunt: Risk-Based OAuth Consent Analysis (Scopes + Burst + Admin)
// Author: Ala Dabat
// Purpose: Detects illicit consent grants by analyzing permission severity and consent bursts (phishing patterns).

let Lookback = 24h;

// High-risk permission indicators
let RiskyScopes = dynamic(["Mail.Read", "Mail.ReadWrite", "Files.Read", "Files.Read.All", "Notes.Read.All", "User.ReadWrite.All", "Directory.ReadWrite.All"]);

// Known safe publishers
let SafePublishers = dynamic(["Microsoft Services", "Microsoft Corporation"]); 

// -------------------
// Consent Base Events
// -------------------
let ConsentEvents = 
    AuditLogs
    | where TimeGenerated > ago(Lookback)
    | where OperationName == "Consent to application"
    | where Result == "success"
    | extend Target = TargetResources[0]
    | extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
    | extend IPAddress = tostring(InitiatedBy.user.ipAddress)
    | extend UserAgent = tostring(InitiatedBy.user.userAgent)
    | extend AppDisplayName = tostring(Target.displayName)
    | extend AppId = tostring(Target.id)
    | mv-apply Prop = Target.modifiedProperties on (
        summarize 
            IsAdminConsent = take_anyif(tostring(Prop.newValue), Prop.displayName == "ConsentContext.OnBehalfOfAll"),
            GrantedScopes  = take_anyif(tostring(Prop.newValue), Prop.displayName == "ConsentContext.Permissions"),
            Publisher      = take_anyif(tostring(Prop.newValue), Prop.displayName == "PublisherName")
    )
    | extend IsAdminConsent = iff(IsAdminConsent =~ "True", 1, 0)
    | extend Publisher = iff(isempty(Publisher), "Unknown", Publisher);

// -------------------------
// Burst: # users per AppId
// -------------------------
let AppPopularity = 
    ConsentEvents
    | summarize ConsentCount = dcount(Initiator) by AppId;

// -------------------------
// Final Risk Scoring
// -------------------------
ConsentEvents
| join kind=leftouter (AppPopularity) on AppId
| extend 
    Score_Admin = iff(IsAdminConsent == 1, 10, 0),
    Score_Scopes = iff(GrantedScopes has_any (RiskyScopes), 10, 0),
    Score_Burst = iff(ConsentCount >= 3, 5, 0),
    Score_Publisher =
        case(
            Publisher in (SafePublishers), 0,
            Publisher == "Unknown", 3,
            5
        )
| extend RiskScore = Score_Admin + Score_Scopes + Score_Burst + Score_Publisher
| where RiskScore >= 5
| extend HunterDirective = case(
    RiskScore >= 20, strcat("CRITICAL: Illicit Consent Grant suspected. Admin permissions (", GrantedScopes, "). Burst: ", ConsentCount),
    RiskScore >= 10, strcat("HIGH: Sensitive scopes granted to '", AppDisplayName, "'."),
    "MEDIUM: Non-standard OAuth consent."
)
| project 
    TimeGenerated, 
    RiskScore, 
    HunterDirective, 
    AppDisplayName, 
    AppId, 
    Initiator, 
    IPAddress, 
    IsAdminConsent, 
    GrantedScopes, 
    ConsentCount, 
    Publisher
| sort by RiskScore desc, TimeGenerated desc

```
<a name="hunt2"></a>

2. Hunt 2 — OAuth Token Theft / Stolen Token Replay
Purpose

Detect token replay and refresh token theft where attackers use existing consents, making Hunt 1 blind.

Threat Indicators

Sign-ins from new countries

New ASNs / cloud providers never seen before

Change in user-agent family (browser → python-requests)

Sudden single-factor authentication (no MFA)

| Behaviour                                                   | Meaning                                    |
| ----------------------------------------------------------- | ------------------------------------------ |
| “Chrome” baseline → sudden “python/requests” UA             | Refresh token stolen + scripted API access |
| Ukraine/Netherlands baseline → new logins from AWS USA-EAST | Token replay from attacker infra           |
| No MFA required                                             | Replay of persistent tokens                |

Sample IOAs

| Behaviour                                                   | Meaning                                    |
| ----------------------------------------------------------- | ------------------------------------------ |
| “Chrome” baseline → sudden “python/requests” UA             | Refresh token stolen + scripted API access |
| Ukraine/Netherlands baseline → new logins from AWS USA-EAST | Token replay from attacker infra           |
| No MFA required                                             | Replay of persistent tokens                |

Sample IOCs

| IOC | Example                |
| --- | ---------------------- |
| ASN | AS14061 (DigitalOcean) |
| ISP | Vultr Holdings         |
| UA  | python-requests/2.31   |


```

// OAuth Token Theft / Replay Detection — Baseline Deviations

let BaselineWindow = 30d;
let RecentWindow   = 7d;
let MinBaseline    = 5;

let Baseline =
SigninLogs
| where TimeGenerated between (ago(BaselineWindow) .. ago(RecentWindow))
| project UserPrincipalName, AppId, AppDisplayName,
          Country=tostring(LocationDetails.countryOrRegion),
          ASN=tostring(NetworkLocationDetails.autonomousSystemNumber),
          UA_Family=toupper(strcat_array(array_slice(split(tostring(UserAgent)," "),0,1),""))
| summarize Count=count(),
            Countries=make_set(Country),
            ASNs=make_set(ASN),
            UAs=make_set(UA_Family)
    by UserPrincipalName, AppId, AppDisplayName
| where Count >= MinBaseline;

let Recent =
SigninLogs
| where TimeGenerated >= ago(RecentWindow)
| project TimeGenerated, UserPrincipalName, AppId, AppDisplayName,
          Country=tostring(LocationDetails.countryOrRegion),
          ASN=tostring(NetworkLocationDetails.autonomousSystemNumber),
          UA=tostring(UserAgent),
          UA_Family=toupper(strcat_array(array_slice(split(tostring(UserAgent)," "),0,1),"")),
          AuthenticationRequirement=tostring(AuthenticationRequirement);

Recent
| join kind=inner Baseline on UserPrincipalName, AppId
| extend NewCountry = iif(Country !in (Countries), 1, 0),
         NewASN = iif(ASN !in (ASNs), 1, 0),
         NewUA = iif(UA_Family !in (UAs), 1, 0)
| extend AnomalyScore =
         (NewCountry * 3) +
         (NewASN * 2) +
         (NewUA * 2) +
         (iif(AuthenticationRequirement =~ "singleFactorAuthentication", 2, 0))
| where AnomalyScore >= 6
| extend Severity = iff(AnomalyScore >= 8, "High", "Medium")
| project 

```

<a name="hunt3"></a>

## 3. Hunt 3 — OAuth Burst Phishing Detection
Purpose

Detect multi-user consent bursts, a clear signature of phishing kits.

IOA Samples

Same malicious AppID shows 5+ consents across HR or Finance

All consents occur within 1–3 hours

Same malicious publisher

# KQL (L1 Simple Version)

```
AuditLogs
| where TimeGenerated >= ago(24h)
| where OperationName == "Consent to application" and Result=="success"
| extend AppDisplayName = tostring(TargetResources[0].displayName),
         AppId = tostring(TargetResources[0].id),
         User = tostring(InitiatedBy.user.userPrincipalName)
| summarize ConsentCount=dcount(User), Users=make_set(User) by AppId, AppDisplayName
| where ConsentCount >= 3
| project AppDisplayName, AppId, ConsentCount, Users
```

<a name="hunt4"></a>

## 4. Hunt 4 — Service Principal Backdoor Detection (Credential Injection)
Purpose

Detect new secrets / credentials added to service principals — a common cloud persistence technique.

Threat Model
Attackers with directory privileges:
Add new secret to SP
Use SP for Graph API access
Bypass user MFA entirely
IOAs
Credential updates on high-value SPs (Graph, Exchange Online)
Credential injection at odd hours
Actor account not normally associated with application management

| IOC Type      | Example                           |
| ------------- | --------------------------------- |
| SP Name       | “Azure AD Sync”                   |
| SP Change     | New KeyIdentifier                 |
| OperationName | Add service principal credentials |


# FULL KQL — Hunt 4

```
// Service Principal Credential Injection (Backdoor)
// Detects new secrets or keys added to SPs

let Lookback = 30d;

AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName in (
      "Add service principal credentials",
      "Update service principal",
      "Update application"
  )
| extend Target = TargetResources[0],
         AppDisplayName = tostring(Target.displayName),
         AppId = tostring(Target.id)
| mv-expand Prop = Target.modifiedProperties
| extend PropName = tostring(Prop.displayName)
| where PropName has_any ("passwordCredentials","keyCredentials","KeyId","KeyIdentifier")
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
            Changes=make_set(PropName), Initiators=make_set(tostring(InitiatedBy.user.userPrincipalName))
      by AppId, AppDisplayName
| extend Severity = iff(array_length(Changes) >= 1, "High", "Medium")
| project AppId, AppDisplayName, Changes, Initiators, Severity, FirstSeen, LastSeen


```
<a name="mitre"></a>

# 5. Full MITRE ATT&CK Mapping

| Hunt                     | Technique | Description                          |
| ------------------------ | --------- | ------------------------------------ |
| Consent Risk (Hunt 1)    | T1078     | OAuth tokens as credentials          |
| Consent Risk             | T1550.001 | Stolen or malicious token abuse      |
| Consent Risk             | T1566.002 | OAuth phishing                       |
| Token Theft (Hunt 2)     | T1550.001 | Replay of tokens from new infra      |
| SP Backdoor (Hunt 4)     | T1098     | SP key injection (cloud persistence) |
| Burst Detection (Hunt 3) | T1566     | Mass-phish behaviour                 |

<a name="sop"></a>

6. Incident Response SOP (L1/L2 Workflow)
Step 1 — Validate the Consent Event

Confirm Initiator identity

Check whether user expected to add apps

Check known business SaaS onboarding tickets

Step 2 — Examine Permissions

If scope contains Mail. or Files.ReadWrite, escalate immediately

If Directory.* or User.* → potential privilege escalation

Step 3 — Check Burst Activity

If multiple users consented in <24h, treat as phishing campaign

Step 4 — Verify Publisher

If not Microsoft or verified ISV → raise risk

Step 5 — Containment Actions

Revoke user sessions

Remove OAuth grant via Azure AD portal

Investigate mailbox/file access post-consent

Step 6 — Escalate to L3

If admin consent, directory-level scopes, or SP credential injection → escalate with P1 severity.

<a name="ioc"></a>

7. IOCs, IOAs, and Malicious Actions Reference
Common Malicious OAuth App Names
“Secure Email Enhancer”
“Microsoft Teams Optimizer”
“Productivity Insights AI”
Suspicious User Agents
python-requests
curl
PostmanRuntime
PowerShell/7.4
Suspicious Publishers
“Global Cloud Solutions”
“TeamSync LLC”
“Unknown” (in most cases)
High-Risk Scopes
Directory.ReadWrite.All
User.ReadWrite.All
Files.ReadWrite.All
Mail.ReadWrite
Mail.Send

# OAuth Threat Hunting Pack — Diagram + Sentinel Workbook
### Author: Ala Dabat
### Version: 2025-12  
This folder contains the **diagrammatic OAuth attack flow** and the full **Sentinel Workbook** that visualizes all four hunts.

---

# 1. OAuth Attack Chain Diagram (Mermaid)

~~~mermaid
flowchart TD
    A[User receives phishing link] --> B{How does user sign in?}
    B -->|Standard login| C[User authenticates]
    B -->|Device code flow| C

    C --> D[OAuth consent page shown]
    D --> E{Does user grant consent?}

    E -->|Yes| F[Malicious app granted scopes]
    E -->|No| H[No attack]

    F --> G{Scope severity}
    G -->|Mail Files Directory| H1[High risk access granted]
    G -->|Low impact scopes| H2[Moderate risk access]

    H1 --> I[Attacker gains token via consent]
    H2 --> I

    I --> J{Attack path}
    J -->|Graph API abuse| K[Mail and data exfiltration]
    J -->|Silent access| L[Persistence via refresh tokens]
    J -->|Privilege escalation| M[Directory manipulation]
    J -->|Service principal abuse| N[New secrets added to service principals]

    K --> O[Long term compromise]
    L --> O
    M --> O
    N --> O

    O --> P[Detection surface]
    P -->|New consent events| Q1[Hunt 1 Consent risk]
    P -->|Token replay| Q2[Hunt 2 Token theft]
    P -->|Burst of consents| Q3[Hunt 3 Burst phishing]
    P -->|SP credential changes| Q4[Hunt 4 SP backdoor]
~~~
