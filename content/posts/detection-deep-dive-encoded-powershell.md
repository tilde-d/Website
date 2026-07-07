+++
title = "Detection Deep Dive: Encoded PowerShell Commands (T1059.001)"
date = 2026-07-07T09:00:00-06:00
draft = false
summary = "The first entry in the Detection Deep Dive series: mapping encoded PowerShell execution to detection logic in Microsoft Defender, tuning out the false positives, and knowing what the detection can't see."
tags = ["detection-deep-dive", "kql", "powershell", "mitre-attack", "defender"]
series = ["Detection Deep Dive"]
+++

This is the first post in **Detection Deep Dive**, a series where I take a single ATT&CK technique, trace how real adversaries use it, build the detection logic, and — the part most write-ups skip — say plainly what the detection *won't* catch.

We're starting with one of the most abused sub-techniques in the matrix: **encoded PowerShell command execution**, [T1059.001](https://attack.mitre.org/techniques/T1059/001/).

## Why attackers reach for `-EncodedCommand`

PowerShell's `-EncodedCommand` (aliases: `-enc`, `-e`) accepts a Base64-encoded, UTF-16LE string and executes it. Attackers love it for three reasons: it defeats naive string-matching on command lines, it survives copy-paste and cross-process handoff cleanly, and it's everywhere by default. Loaders, C2 stagers, and living-off-the-land scripts all lean on it.

Here's what a benign encoded invocation looks like decoded:

```powershell
# What the operator typed (harmless example):
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvACIA

# Decoding the Base64 (UTF-16LE) yields:
Write-Host "hello"
```

The tell isn't the payload — it's the *shape* of the invocation: a Base64 blob passed to an encoding flag.

## The detection

Here's a starting-point KQL detection for Microsoft Defender XDR / Advanced Hunting. It looks for the encoding flags across PowerShell process launches:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-e(nc(odedcommand)?)?\s"
| extend AccountUpn = tostring(AccountName)
| project
    Timestamp,
    DeviceName,
    AccountUpn,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by Timestamp desc
```

A few deliberate choices:

- `in~` and the `(?i)` flag keep the match **case-insensitive** — attackers mix case (`-EnCoDeD`) specifically to dodge case-sensitive rules.
- Matching the flag family (`-e`, `-enc`, `-encodedcommand`) with one regex catches all abbreviations PowerShell accepts.
- Pulling `InitiatingProcessCommandLine` gives you the **parent context** — a Word document spawning encoded PowerShell is a very different story from a sanctioned admin script.

## Tuning: the false positives you *will* get

Encoded PowerShell is not inherently malicious. Plenty of legitimate software uses it. If you deploy the query above raw, you'll drown. Here's where the real detection-engineering work is:

| Source of FP | How to handle it |
|---|---|
| Endpoint management (SCCM, Intune) | Baseline the initiating process; allowlist known management parents |
| Vendor agents & installers | Allowlist by signed publisher + expected path |
| Scheduled tasks from IT | Correlate against known task GUIDs |
| Your own detection tooling | Exclude your SOAR / automation service accounts |

A more production-shaped version layers exclusions on top:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-e(nc(odedcommand)?)?\s"
// --- environment-specific allowlist; tune to YOUR baseline ---
| where InitiatingProcessFileName !in~ ("ccmexec.exe", "intunemanagementextension.exe")
| where not(AccountName has_any ("svc-soar", "svc-automation"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

Don't copy those exclusions blindly — they're placeholders. The point is the *method*: baseline first, then subtract the known-good.

## What this detection can't see

Every honest detection write-up needs this section. Attackers who know you're watching for `-EncodedCommand` will:

- **Skip the flag entirely** and pipe a decoded string to `Invoke-Expression`, assembling it from concatenated fragments at runtime.
- **Use alternate execution** — `System.Management.Automation` reflectively loaded inside another process, so `powershell.exe` never appears on a command line at all.
- **Downgrade to PowerShell v2** to evade script-block logging (`-Version 2`), which is itself a stronger detection signal than the encoding.

The durable lesson: command-line detection is a tripwire for the lazy and the noisy, not a wall against the careful. Pair it with **script-block logging** (Event ID 4104) and AMSI telemetry, which see the *decoded* content regardless of how it was passed in. That's a deep dive for a future post.

## Takeaways

Encoded PowerShell is cheap to detect at the command-line layer and cheap to evade at the same layer — which is exactly why it belongs in a layered stack, not as a standalone control. Ship the tripwire, tune it against your baseline, and back it with content-layer visibility.

Next in the series: turning script-block logs into a detection that survives the evasions above.

*Have a technique you want covered? Find me on [GitHub](https://github.com/tilde-d) or [email](mailto:matt@mattswann.dev).*
