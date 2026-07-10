+++
title = "5 KQL Queries to Slash Your Containment Time in Microsoft Sentinel"
date = 2026-01-05T09:18:38-07:00
draft = false
summary = "In an active breach, speed is everything. These five KQL queries — covering file drops, identity compromise, lateral movement, C2 beaconing, and persistence — are designed for the first hour of incident response."
tags = ["kql", "incident-response", "detection-engineering", "sentinel", "defender"]
canonicalURL = "https://medium.com/@mattcswann/5-kql-queries-to-slash-your-containment-time-in-microsoft-sentinel-57bb81b52551"
+++

In an incident response scenario, **time is your most critical resource.** Every second spent deliberating is another second an attacker has to move toward their objective. As the clock ticks, the potential cost to the organization grows exponentially.

Defenders operate within a unique dichotomy: our defensive actions are almost always **bounded** in their negative impact, while an attacker's actions are **unbounded.** Consider a common scenario: you receive an alert for potential malware on a workstation. The primary indicator is an oddly named executable with multiple hits on VirusTotal. You have two choices:

1. **Immediate isolation.** You isolate the host immediately. The downside is a temporary disruption to one user's productivity while you investigate. This impact is small, known, and bounded.
2. **Delayed analysis.** You spend 30 minutes "being sure" before disrupting the user. If that file is a ransomware dropper, those 30 minutes could allow the threat to spread across the entire domain. The impact here is unbounded — including potentially the total encryption of the corporate network.

This is the fine line incident responders must walk. Success in the midst of an incident isn't about knowing *everything*; it's about knowing *enough* to take rapid, defensible, and reversible actions that minimize the blast radius.

The following five queries are designed to get you there fast.

---

## 1. File Creations and Modifications

```kql
DeviceFileEvents
| where DeviceName contains "<DeviceName>"
| where ActionType has_any("FileCreated", "FileModified")
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

Starting with a "no-brainer" might seem simple, but its utility cannot be overstated. In incident response, the goal is to achieve **situational awareness** as fast as possible. While fileless malware is a valid threat, the vast majority of classic intrusions still rely on staged droppers to execute their objectives.

Running this in a narrow window — +/- 1 hour around the initial alert — is often the fastest way to confirm malicious intent.

**Real-world application:** This isn't just hypothetical; this exact hunting query helped provide a high level view into attacker activity in a suspected ransomware intrusion in an environment. Following initial access, the following attack chain was observed:

1. Creation of a suspicious `.zip` archive in the user's `Downloads` folder.
2. Appearance of a `.lnk` file masquerading as a text document.
3. An explosion of Python `.pyd` (dynamic modules) and `.pyc` (compiled bytecode) files.

That sequence immediately signaled a Python-based installer. Subsequent forensics confirmed a PowerShell dropper — the masqueraded `.lnk` — had reached out to a GitLab repository to pull down a Python bootloader executable.

Never underestimate the actionable insight gained from simply looking at the dirt to see what's been moved. Often times it's simple hunting queries like this that help you quickly gain your bearings in an incident.

**Impact:** Drastically reduces Mean Time to Identify (MTTI) by pinpointing the exact landing time of a threat, enabling an immediate shift from general hunting to surgical remediation of malicious artifacts.

---

## 2. Successful Sign-Ins

```kql
SigninLogs
| where UserPrincipalName contains "<User@Domain.com>"
| where ResultSignature contains "SUCCESS"
| project TimeGenerated, IPAddress, Location, AppDisplayName, UserAgent
| sort by TimeGenerated desc
```

While Query 1 focuses on the host, this one focuses on **identity.** In a perimeter-less environment, a compromised credential is often more dangerous than a compromised workstation.

This returns the "Big Four" artifacts of a login: source IP, geolocation, application accessed, and User Agent string. Together they let you quickly determine whether a login aligns with known user patterns or represents an anomaly.

**Prioritizing action over noise:** You'll notice this filters specifically for *successful* logins. A barrage of failed logins from a malicious IP is worth investigating, but it doesn't demand an immediate emergency response. A *successful* login from an unknown IP is much more indicative of an actual breach.

Seeing a confirmed malicious successful login lets you pull the most effective defensive levers immediately:

- Credential rotation
- Session revocation
- Account disablement

By ignoring the noise of failed attempts during the heat of an incident, you focus energy on the actual foothold.

**Impact:** Prevents account takeover escalation by immediately identifying compromised identities — enabling session suspension before an attacker can pivot from a single user to a Global Admin or sensitive resource.

---

## 3. Blast Radius Assessment (Lateral Movement)

```kql
let lookback = 2h;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| summarize hosts = make_set(DeviceName), executions = count()
      by FileName, FolderPath
| where FileName contains "<malicious filename here>"
| where array_length(hosts) > 1
| order by executions desc
```

Once Patient Zero is contained, the clock starts on a new race: finding where else the attacker has landed. If you've identified a malicious executable on the initial host, this query instantly scans the rest of the environment for that same file.

The default lookback is 2 hours but can be adjusted based on your alert timeline. By grouping on `FileName` and `FolderPath`, you can quickly determine whether the threat is isolated or spreading.

**The Pyramid of Pain caveat:** Seasoned defenders know filenames sit at the bottom of the Pyramid of Pain — trivial for an attacker to change. But in the heat of an active incident, attackers often get sloppy or rely on automated scripts that reuse names. If you notice a pattern like `Update_batch_v1.exe`, `Update_batch_v2.exe`, you can easily broaden the `where FileName` clause to look for the common prefix.

We aren't writing a long-term detection rule here. We're looking for quick wins to prevent a localized infection from becoming a site-wide disaster.

**Impact:** Minimizes total cost of breach by identifying silent infections on adjacent hosts, ensuring cleanup is comprehensive and preventing the re-infection loops that occur when a threat is only partially evicted.

---

## 4. High-Value Asset Discovery (Account-Based Lateral Movement)

```kql
DeviceLogonEvents
| where AccountName contains "<CompromisedAccount>"
| where ActionType == "LogonSuccess"
| summarize LastLogon = max(Timestamp), LogonCount = count() by DeviceName, LogonType
| sort by LastLogon desc
```

Once a compromised account is identified, the next question is: **where did they go?** This query maps the footprint of a compromised identity across your physical and virtual assets.

While Query 2 looked at *entry* into the environment via Entra ID, this one looks at *movement within* the environment at the endpoint layer. By identifying every host where the attacker successfully authenticated, you build a containment checklist.

**Pro tip:** If you see `LogonType == Network` or `LogonType == RemoteInteractive`, the attacker is likely moving laterally via the network rather than sitting at a physical keyboard. This differentiates a local user's activity from a threat actor's island hopping, and changes how you prioritize containment.

**Impact:** Rapidly maps the attacker's footprint across the network, allowing the IR team to prioritize isolation of high-value servers or workstations touched by a compromised credential.

---

## 5. Identifying Outbound C2 "Heartbeats"

```kql
DeviceNetworkEvents
| where DeviceName contains "<DeviceName>"
| where RemoteIPType == "Public"
| summarize
    ConnectionCount = count(),
    UniquePorts = dcount(RemotePort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP, RemoteUrl
| where ConnectionCount > 5
| sort by ConnectionCount desc
```

If an attacker has established a foothold, they need to communicate with their infrastructure. This query looks for **beaconing** — repeated, high-frequency outbound connections from a specific host to a public IP or URL.

A host contacting a specific external IP dozens of times in a short window has likely established a **Command and Control (C2) channel.** Blocking that IP at the firewall while you remediate the host is the final step in severing the attacker's control over your environment.

**Impact:** Severs the attacker's control over the environment. Identifying and blocking C2 channels at the network level effectively blinds the threat actor while host-level cleanup is finalized.

---

## Bonus: Identifying Common Persistence Mechanisms

The five queries above are built for the first hour — gaining situational awareness and containing the blast radius fast. Once that's done, it's worth confirming whether the attacker established persistence mechanisms that could let them re-enter after you've booted them out.

These two cover the most common ones: AutoRun registry keys and scheduled tasks.

**AutoRun Registry Keys (T1547.001)**

```kql
DeviceRegistryEvents
| where DeviceName contains "<DeviceName>"
| where RegistryKey contains @"\\Microsoft\\Windows\\CurrentVersion\\Run"
    or RegistryKey contains @"\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp desc
```

**Scheduled Task Creation (T1053.005)**

```kql
DeviceProcessEvents
| where DeviceName contains "<DeviceName>"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any("/create", "/change", "/run")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

**Impact:** Ensures long-term eradication. Clearing persistence mechanisms prevents the threat actor from "waking up" a secondary backdoor weeks after the initial incident is closed.

---

## Takeaway

In the high-pressure environment of an active breach, the difference between a minor incident and a catastrophic headline is often the speed of the responder. KQL is more than a search language — it's a surgical tool that lets you cut through the fog of war and isolate signal from noise.

These queries cover everything from initial file drops and identity compromise to lateral movement, C2 beaconing, and persistence. They're designed for the first hour of response. They aren't meant to be exhaustive forensic reports; they're meant to produce **actionable intelligence fast.**

The goal of a defender is simple: **know enough to act, and act fast enough to win.**

*Originally published on [Medium](https://medium.com/@mattcswann/5-kql-queries-to-slash-your-containment-time-in-microsoft-sentinel-57bb81b52551).*
