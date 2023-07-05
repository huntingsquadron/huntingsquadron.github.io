---
layout: post
title:  "New GuLoader campaign against Polish institutions - analysis of first stages"
date:   2023-07-05 11:32:00 +0800
author: Lasq
categories: malware analysis
tags: malware_analysis, reverse_engineering, ghidra, guloader, malware
published: false
---

# Background

Following GuLoader sample was recently published by Piotr Kowalczyk from CERT Orange Polska:

https://twitter.com/pmmkowalczyk/status/1675806993057996802


https://www.virustotal.com/gui/file/8bce65195a07ca72693f21081aa1d86deb2fdd5784d0e666c0833a9f9bdaf78d/detection

Zapytaine ofertowe Testosteel.vbs

MD5		5fdfd66abc4117ff9f97bce487cf4f7d
SHA-1	24b9df693585b218a447130ec3f385b9225af6d2
SHA-256	8bce65195a07ca72693f21081aa1d86deb2fdd5784d0e666c0833a9f9bdaf78d

This campaign seem to be targeting Polish institusions with .vbs based payloads.

In this post we will analyze first phases of the intrusion, and try to decrypt the final shellcode.

# VBS to Powershell

The initial .vbs code is not very complicated or even obfuscated. It simply contatenates multiple strings to get an obfuscated powershell code that it then executes with use of `WScript.Shell`

![VBS code](/assets/img/2023-07-05-guloader-polish-first-stages/01_vbs.png)

# Powershell stage 1

After putting the strings together, obfuscated powershell looks like this:

![Powershell stage 1 obfuscated](/assets/img/2023-07-05-guloader-polish-first-stages/02_powershell_stage1_obfuscated.png)

We can apply some automatic and manual deobfuscation to clean the code and see what it really does. Below is deobfuscated abd cleaned version:

![Powershell stage 1 deobfuscated and cleaned](/assets/img/2023-07-05-guloader-polish-first-stages/03_powershell_stage1_deobfuscated.png)

As we can see it first checks if it is executed in a 32-bit version of powershell (this is important, since it will inject a 32-bit shellcode), and if not it executes a 32-bit version.

After, we can see a simple download cradle using Bits-Transfer to download next stage payload from external address.

What is relevant here, and (as far as I can tell) specific to GuLoader, it downloads a base64 encoded blob that contains of 3 parts:

1. First short part (usually 400-800 bytes) of the shellcode, which serves as a decryption stub for a second part
2. Encrypted second part of shellcode (main loader code)
3. A plaintext powershell code, that will serve as stage 2 code to inject and execute shellcode inside powershell process memory


The decoded base64 value is being stored in the variable `$Brdmaskin180` - this will be importan when analyzing a second stage shellcode.

In the end, second stage shellcode is extracted from the base64 decoded value with `[System.Text.Encoding]::ASCII.GetString()` and executed with `iex`

# Powershell stage 2

Stage 2 of powershell code, is also obfuscated:

![Powershell stage 2 obfuscated](/assets/img/2023-07-05-guloader-polish-first-stages/04_powershell_stage2_obfuscated.png)

After deobfuscation and clean-up, this is how the code looks like:

![Powershell stage 2 deobfuscated and cleaned](/assets/img/2023-07-05-guloader-polish-first-stages/05_powershell_stage2_deobfuscated.png)


There is quite a lot to unroll here. 