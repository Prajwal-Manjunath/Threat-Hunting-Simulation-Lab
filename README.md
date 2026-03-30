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

This is how you build a process tree — and a process tree is how you reconstruct an attack chain.

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
| Persistence mechanism | 🔄 Pending | Registry Run key - investigation continues |

---

## 🔄 Phase 2 — Execution (In Progress)
*Decoding the Base64 encoded PowerShell command to confirm what was executed.*

---

## 🔄 Phase 3 — Persistence (In Progress)
*Hunting for the registry Run key written under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.*

---

## 🔄 Final Attack Chain
*To be completed after all phases.*

---

## 🔄 Scope & Impacted Assets
*To be completed after full investigation.*

---
