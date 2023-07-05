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

