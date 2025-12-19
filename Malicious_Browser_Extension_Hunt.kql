//////////////////////////////////////////////////////////////////////////////////////////////
// Browser Extension Threat Detection — Behaviour + External Feed (Integrated)
// Rule Title: Browser_Extension_Threat_Detection
// Author: Ala Dabat
// Version: 2025-11
// Category: Persistence / Initial Access / Supply-Chain
// MITRE: T1176 (Browser Extensions), T1546 (Event Triggered Execution), T1059 (Script Execution)
//
// Description:
//     Integrated detection for malicious browser extensions combining behavioural surfaces
//     (CRX installers, extension folder creation, manifest writes, forced installs) with a
//     known-malicious extension feed. Includes scoring, MITRE mapping, and SOC-ready directives.
//
// CPU Profile:
//     Behaviour Surface: Low CPU
//     Feed Correlation: Medium CPU
//////////////////////////////////////////////////////////////////////////////////////////////

let lookback = 7d;

// ---------------------------------------------
// Malicious Extension Feed (External Repository)
// ---------------------------------------------
let MaliciousExtensions = externaldata (
    browser_extension: string,
    browser_extension_id: string,
    metadata_category: string,
    metadata_type: string,
    metadata_link: string,
    metadata_comment: string
)
["https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/Browser%20Extensions/browser_extensions_list.csv"]
with (format="csv", ignoreFirstRecord=true)
| extend FeedExtensionID = trim(" ", tolower(browser_extension_id))
| where isnotempty(FeedExtensionID)
| extend FeedThreatWeight = case(
        metadata_type == "malicious", 3,
        metadata_type == "vulnerable", 1,
        0
    );

// ---------------------------------------------
// Behavioural Surfaces (CRX, Folders, Manifest, Forced Installs)
// ---------------------------------------------
let BehaviourEvents =
(
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where FileName endswith ".crx" and ActionType == "FileCreated"
    | extend ExtractedID = tolower(extract(@"([a-z0-9]{32})", 1, FileName)), InstallMethod="CRXInstaller"

    union

    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where ActionType in ("FileCreated","FolderCreated")
    | where FolderPath has @"\Extensions\" and FolderPath has @"User Data"
    | extend ExtractedID = tolower(extract(@"\\Extensions\\([a-z0-9]{32})\\", 1, FolderPath)), InstallMethod="ExtensionFolder"

    union

    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "manifest.json" and FolderPath has @"\Extensions\"
    | extend ExtractedID = tolower(extract(@"\\Extensions\\([a-z0-9]{32})\\", 1, FolderPath)), InstallMethod="ManifestWrite"

    union

    DeviceRegistryEvents
    | where Timestamp >= ago(lookback)
    | where RegistryKey has "ExtensionInstallForcelist"
    | extend ExtractedID = tolower(extract(@"([a-z0-9]{32})", 1, tostring(RegistryValueData))), InstallMethod="PolicyForceInstall"
)
| where isnotempty(ExtractedID)
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, RegistryKey, RegistryValueData, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256, InstallMethod, ExtractedID;

// ---------------------------------------------
// Join Behavioural Surface with Malicious Feed
// ---------------------------------------------
let MatchedFeed =
BehaviourEvents
| join kind=leftouter (MaliciousExtensions) on $left.ExtractedID == $right.FeedExtensionID
| extend IsFeedMatched = iff(isnotempty(FeedExtensionID), 1, 0);

// ---------------------------------------------
// Scoring Logic (Hybrid: Feed + Behaviour)
// ---------------------------------------------
let Scored =
MatchedFeed
| extend BehaviourWeight = case(
        InstallMethod == "PolicyForceInstall", 3,
        InstallMethod == "ManifestWrite",      2,
        InstallMethod == "CRXInstaller",       1,
        InstallMethod == "ExtensionFolder",    1,
        0
    )
| extend TotalScore = BehaviourWeight + FeedThreatWeight;

// ---------------------------------------------
// MITRE + ThreatHunterDirective
// ---------------------------------------------
let FinalOutput =
Scored
| extend MITRE_Technique = case(
        InstallMethod == "PolicyForceInstall", "T1176;T1546",
        InstallMethod == "ManifestWrite",      "T1176;T1059",
        "T1176"
    )
| extend ThreatHunterDirective = case(
        IsFeedMatched == 1 and FeedThreatWeight == 3, "CRITICAL: Known malicious extension installed. Isolate device immediately and investigate user activity.",
        IsFeedMatched == 1 and FeedThreatWeight == 1, "HIGH: Vulnerable or high-risk extension detected. Audit extension behaviour and confirm legitimacy.",
        InstallMethod == "PolicyForceInstall",        "CRITICAL: Forced extension install detected. Validate GPO and investigate for policy abuse.",
        InstallMethod == "ManifestWrite",             "HIGH: manifest.json modification detected. Inspect extension folder and process lineage.",
        InstallMethod == "CRXInstaller",              "MEDIUM: CRX installer used. Confirm user intent.",
        InstallMethod == "ExtensionFolder",           "MEDIUM: Extension folder creation event. Review for stealth installs.",
        "INFO: Review event if user reports browser issues."
    );

FinalOutput
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, ExtractedID, browser_extension, metadata_category, metadata_type, metadata_link, metadata_comment, InstallMethod, IsFeedMatched, TotalScore, MITRE_Technique, ThreatHunterDirective
| order by Timestamp desc

// Project: https://github.com/azdabat/Threat-Hunting-Rules/BrowserExtensions
