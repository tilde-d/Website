+++
title = "Detecting Suspicious RMM Tool Execution Chains in Microsoft Defender (T1219)"
date = 2026-07-10T09:00:00-06:00
draft = false
summary = "One of the most common initial access vectors into environments by threat actors is through use of legitimate RMM tooling, offering both hands-on-keyboard access as well as stealth. Read more below for some considerations on detecting such activity."
tags = ["detection-deep-dive", "kql", "powershell", "mitre-attack", "defender", "rmm", "ransomware"]
series = ["Detection Deep Dive"]
+++

Gone are the days where the first sign of a possible intrusion are an alert for a malicious executable - `malware.exe`, for example - being run in your environment. If your current posture fits this description, when you finally get that alert, you will find yourself playing catch-up against an attacker who is already multiple steps ahead, fighting a losing battle. We can do better.

## The Shifting Threat Landscape

Today's threat landscape is evolving more rapidly than ever before, and looking back even just a handful of years showcases this. AI tooling is commonplace, organizations are taking an ever-increasing cloud-first or hybrid approach, workforces are becoming more spread as remote work rises in popularity, and the baseline level of security that computing systems ship with is increasing (don't grab your pitchforks just yet - hear me out). 

All of the above have drastically reduced one attack surface, while simultaneously creating another more nefarious one. "Older" anti-malware solutions relied on simplistic detection methods such as signature analysis, hash-based detections, and other static methods, allowing capable attackers plenty of opportunity to design malware to evade EDR detection. Modern EDR solutions possess much more powerful features including in-memory tamper detection, AMSI for scan-time inspection of scripts, kernel callbacks for monitoring the OS, and much more.

Enter the new control plane: **Identity.** Unlike an endpoint, there is no EDR solution for identities. You cannot as easily detect a so-called "infected" account in the same manner you would detect an infected endpoint. The heavy adoption of the cloud and SaaS-like workloads has also greatly opened up the perimeter: whereas endpoint and assets could sit safely behind a firewall, cloud-based tooling like Microsoft 365, Azure, AWS, Google Cloud and more are all just one publicly-accessible login panel away from granting someone external access to company resources. **Why would an attacker spend energy trying to bypass firewall rules to gain a foothold on a device, just to plant malware that will most likely be blocked by EDR, when all they need is access to a single user's cloud identity to be handed the keys to the kingdom?** 

Every single annual threat report -- CrowdStrike's **Global Threat Report**, Verizon's **Data Breach Investigations Report**, Huntress' **Cyber Threat Report**, and more -- agrees that cloud and identity is the new control plane attackers are most commonly targeting. So how does this influence what we do as defenders?

## Legitimate Tooling, Bad Intentions

Attackers are smart. They know what defenders are looking for in their logs and alerts. They are well aware that running BloodHound (or insert your favorite *Hound flavor here) is the quick ticket to being booted out the door, and this is where legitimate tooling comes in. Attackers know that virtually every single organization has a legitimate need to use one or more **Remote Access / Remote Monitoring & Management (RMM)** tool in their environment. This allows threat actors the ability to leverage RMM tools as a sort of pseudo-LOLBin, as RMM tool activity is likely weakly monitored, if at all, by defenders, and from the EDR perspective, any legitimate and signed RMM tool will typically slip past detections from the viewpoint of "does this binary perform suspicious or malicious activity by itself?".

Usage of legitimate RMM tooling by threat actors to blend into an environment and conceal their activity is well documented, with many reports showing suspicious commands either as direct child processes from an RMM tool process, or as a child of an intermediary command line process such as `cmd.exe` or `powershell.exe` spawning from the RMM tool. Why the variance? The two-tiered approach makes sense: attacker gains interactive session, immediately begins performing actions on objective. The three-tiered approach may be even more sinister: imagine you're an attacker who phished a user pretending to be IT help desk, and this particular user has local admin privileges - if you can talk the user into spawning a PowerShell console as admin, you just let the victim carry out local privilege escalation for you. This two- and three-tiered activity is precisely what we'll spend the rest of this article discussing.


## Detecting Suspicious RMM Tooling Process Trees in Defender Using KQL

As just discussed, from a process tree artifact perspective, RMM tooling abuse can take two main forms: RMM tool parent with an immediately suspicious child, or RMM grandparent, command-line tool parent, and suspicious child process. The former two-tiered approach is somewhat trivial to detect (though also significantly more prone to FPs, so ensure to tune accordingly), so we'll focus on the more complex three-tiered approach. We can use the generalized three-tiered process tree below as an example:

```
RMMtool.exe  (AnyDesk / ScreenConnect / RMM tool)
└─ cmd.exe   (command line interpreter)
   └─ net.exe  (suspicious recon command)
```

We can use this process tree as the backbone to build the following three-tiered detection query:

```kql
let RmmTools = dynamic([
    "anydesk.exe",
    "ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe",
    "bomgar-scc.exe",
    "AteraAgent.exe",
    "SRService.exe",
    "client32.exe",
    "rutserv.exe", "rfusclient.exe"
]);
let ConsoleTools = dynamic(["cmd.exe","powershell.exe","pwsh.exe","powershell_ise.exe"]);
let ReconTools = dynamic([
    // Recon / discovery
    "net.exe","net1.exe","whoami.exe","nltest.exe","systeminfo.exe",
    "ipconfig.exe","arp.exe","netstat.exe","tasklist.exe",
    "quser.exe","qwinsta.exe","nslookup.exe","dsquery.exe","wmic.exe",
    // Proxy execution
    "rundll32.exe","regsvr32.exe","mshta.exe","msiexec.exe",
    "installutil.exe","regasm.exe","regsvcs.exe",
    // Script hosts
    "wscript.exe","cscript.exe",
    // Ingress / transfer
    "certutil.exe","bitsadmin.exe","curl.exe",
    // Persistence / services
    "schtasks.exe","sc.exe","at.exe",
    // Credential access / destruction
    "reg.exe","vssadmin.exe","wbadmin.exe","ntdsutil.exe"
]);
// Tier 1 — RMM tool (grandparent)
let Tier1_RMM =
    DeviceProcessEvents
    | where FileName in~ (RmmTools)
    | project DeviceId, DeviceName,
        RmmFileName     = FileName,
        RmmProcessId    = ProcessId,
        RmmCreationTime = ProcessCreationTime,
        RmmCommandLine  = ProcessCommandLine,
        RmmFolderPath   = FolderPath,
        RmmAccount      = AccountName;
// Tier 2 — console spawned by the RMM (parent)
let Tier2_Console =
    DeviceProcessEvents
    | where FileName in~ (ConsoleTools)
    | project DeviceId,
        ConsoleFileName       = FileName,
        ConsoleProcessId      = ProcessId,
        ConsoleCreationTime   = ProcessCreationTime,
        ConsoleCommandLine    = ProcessCommandLine,
        ConsoleParentId       = InitiatingProcessId,
        ConsoleParentCreation = InitiatingProcessCreationTime,
        ConsoleParentFileName = InitiatingProcessFileName;
// Tier 3 — recon spawned by the console (child)
let Tier3_Recon =
    DeviceProcessEvents
    | where FileName in~ (ReconTools)
    | project DeviceId,
        ReconTime           = Timestamp,
        ReconReportId       = ReportId,
        ReconFileName       = FileName,
        ReconProcessId      = ProcessId,
        ReconCreationTime   = ProcessCreationTime,
        ReconCommandLine    = ProcessCommandLine,
        ReconAccount        = AccountName,
        ReconParentId       = InitiatingProcessId,
        ReconParentCreation = InitiatingProcessCreationTime,
        ReconParentFileName = InitiatingProcessFileName;
Tier1_RMM
| join kind=inner Tier2_Console on
    DeviceId,
    $left.RmmProcessId    == $right.ConsoleParentId,
    $left.RmmCreationTime == $right.ConsoleParentCreation
| join kind=inner Tier3_Recon on
    DeviceId,
    $left.ConsoleProcessId    == $right.ReconParentId,
    $left.ConsoleCreationTime == $right.ReconParentCreation
| project
    Timestamp = ReconTime, DeviceId, DeviceName, ReportId = ReconReportId, ReconAccount,
    RmmFileName,     RmmProcessId,     RmmCommandLine,
    ConsoleFileName, ConsoleProcessId, ConsoleCommandLine,
    ReconFileName,   ReconProcessId,   ReconCommandLine
| sort by Timestamp desc
```

Because Microsoft Defender only gives us the parent/child process relationship in a single log entry, we need to marry the `DeviceProcessEvents` table to itself, ensuring we are mapping DeviceId's and processes properly, in order to obtain the grandparent/parent/child process relationship instead. This query starts by identifying the **grandparent** process as one of a few selected RMM tools (a list of RMM tools documented as known to be abused by threat actors, though certainly not exhaustive), a subsequent **parent** process of a command line interpreter such as `cmd` or `PowerShell`, and finally a **child** process of known suspicious commands executed once an attacker has hands-on-keyboard access into an environment.

One quick note on tools in `ReconTools`: less critical tooling such as `whoami` or `net` are looped into the same list as potentially more concerning tooling -- `vssadmin`, `msiexec`, `ntdsutil`, and so on -- and currently no weighting exists to highlight the latter as being more concerning than the former. If desired, this query can be modified to assign a weight to various child commands to highlight those that may be of more concern than others.

One unfortunate side effect of needing to join the table to itself removes the ability for this alert to fire at Near Real Time (NRT). However, Defender gives you the option to select a "custom" timeframe, with the lowest value being every 5 minutes. I'd say a potential 5 minute delay to catching activity is worth it if the alternative is missing it completely and waiting for something worse to happen.

## Why This Works, and the Tuning Caveat

As defenders, we have one specific advantage over attackers: they will **always** need to perform certain actions throughout their process to reach their ultimate objective, and these are known actions (thanks Cyber Kill Chain and MITRE ATT&CK) that leave behind easily identifiable evidence. That is precisely what makes this query so powerful. 

When an attacker first gains an interactive foothold in an environment using an RMM tool, in their best case scenario they know the user's role (assuming they phished this person, gathered OSINT on them from LinkedIn, for example) and can make an assumption about the permissions they have. That could lead to a lot of banging on doors to test access, likely firing alerts in the process. In the worst case, they know nothing about the user they compromised (brute forced a random account, bought creds off the dark web), and need to gain some idea of what permissions they have to avoid raising suspicion.  Either way, it is almost guaranteed that some sort of local reconnaissance will be performed once the foothold is gained, and this query catches that activity immediately.

When it comes to **tuning**, it goes without saying that before deploying this query, it should be tested in the environment and any false positives should be identified and tuned out accordingly. For example, if an organization leverages a specific RMM tool for help desk to go in and troubleshoot local admin privileges, a help desk member using said RMM tool to spawn a command line prompt and run `net localgroup Administrators` or something similar will obviously fire this detection, and should be carefully tuned out, ensuring to not leave the tune too broad such that it misses similar, though unrelated activity.

## The Bigger Picture

This detection is narrow by design, but it serves to highlight the importance of defense in depth, and having the ability to catch and stop an attacker at multiple points along the kill chain for any specific attack. As we've highlighted the shift in how we have to think as defenders, we must remember that the same logic that pushes an attacker toward a stolen cloud identity also pushes them toward a trusted RMM agent on the endpoint: in both cases, they are trading loud, detectable malware for quiet, legitimate access. Malware announces itself; legitimacy does not. The job is no longer about just catching bad binaries. As the perimeter continues to dissolve and "trusted" tooling becomes the attacker's tooling of choice, the highest-value detections are the ones that flag *legitimate tools behaving illegitimately* - exactly what this query is built to catch.