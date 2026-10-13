# Multi-Stage AES Encrypted PowerShell Loader Analysis

## Overview

This document details the analysis of a heavily obfuscated PowerShell command identified during investigation. The script leverages AES encryption, multiple layers of payload staging, PowerShell in-memory execution, and network communication capabilities to retrieve and execute additional content.

Based on the observed behavior, the script exhibits characteristics commonly associated with malware loaders, ClickFix-style attacks, and staged payload delivery frameworks.

---

# Initial Execution Command

The PowerShell execution chain starts with the following components:

```powershell
$k61ba = [System.Convert]::FromBase64String(...)
$i9da7 = [System.Convert]::FromBase64String(...)
$eafb0 = [System.Convert]::FromBase64String(...)

$a7787 = New-Object System.Security.Cryptography.AesManaged
$a7787.Key = $k61ba
$a7787.IV  = $i9da7

iex(
    [System.Text.Encoding]::UTF8.GetString(
        $a7787.CreateDecryptor().TransformFinalBlock(
            $eafb0,
            0,
            $eafb0.Length
        )
    )
)
```

---

# Attack Flow

```text
Base64 Encoded Data
        │
        ▼
AES Key + IV Decoding
        │
        ▼
AES Payload Decryption
        │
        ▼
UTF8 Conversion
        │
        ▼
Invoke-Expression (IEX)
        │
        ▼
Second Stage PowerShell
        │
        ▼
Additional AES Payloads
        │
        ▼
HTTP Requests
        │
        ▼
Payload Download
        │
        ▼
Execution / Persistence
```

---

# Stage 1 Analysis

## Purpose

The first layer performs:

1. AES key decoding
2. AES payload decryption
3. In-memory execution

No payload is initially written to disk.

## AES Configuration

### Key

```text
32 Bytes
```

Equivalent to:

```text
AES-256
```

### IV

```text
16 Bytes
```

### Cipher Mode

Most likely:

```text
AES-CBC
```

Based on the implementation of:

```powershell
System.Security.Cryptography.AesManaged
```

---

# Layer 1 Decryption Results

After decrypting the initial payload, several additional encrypted elements were identified.

## Discovered AES Blobs

```powershell
$u2b476k
$u2b476i
$u2b476e

$u49de2k
$u49de2i
$u49de2e
```

Each group contains:

| Variable | Purpose |
|-----------|-----------|
| *k | AES Key |
| *i | AES IV |
| *e | Encrypted Payload |

This indicates the payload contains multiple decryption stages.

---

# String Obfuscation

The author intentionally avoided storing strings directly.

## Example

```powershell
$n47ca='Op'+'en'
$n9bc2='Se'+'nd'
$n4f32='Re'+'sponseBody'
$n2f51='WriteA'+'llBytes'
```

Resolved values:

```text
Open
Send
ResponseBody
WriteAllBytes
```

## Purpose

This technique is designed to:

- Evade static analysis
- Reduce signature effectiveness
- Complicate IOC extraction
- Bypass simple PowerShell detections

---

# Network Function Creation

A function is built dynamically within the decrypted payload.

```powershell
$nb56b = {
    param($u)

    $wc.Open('GET',$u,0)
    $wc.Send()
    $wc.ResponseBody
}
```

## Purpose

Performs:

```text
HTTP GET Request
```

and returns:

```text
Raw Content From Remote Server
```

---

# Delayed Execution

The payload intentionally pauses before continuing execution.

```powershell
Start-Sleep -Seconds 16
```

## Common Adversary Objectives

### Sandbox Evasion

Many sandboxes only observe processes for a short duration.

### Behavioral Detection Evasion

Delays network activity until after initial inspection.

### Payload Synchronization

Allows remote operators additional time.

---

# Additional Decoded Content

## Base64 String

```powershell
d2FyZGVu
```

Decoded value:

```text
warden
```

## Possible Significance

The value may represent:

- Campaign identifier
- Operator keyword
- Internal payload label
- Decryption reference

Further stages would be required to determine its exact role.

---

# Observed Techniques

## Encryption

### AES Protected Payload

```text
AES-256
```

used to conceal embedded PowerShell.

### Benefits To The Attacker

- Prevents signature matching
- Delays analyst understanding
- Defeats simple file scanning

---

## In-Memory Execution

### Technique

```powershell
Invoke-Expression (IEX)
```

### Benefits To The Attacker

- No executable dropped to disk
- Reduced forensic artifacts
- Bypass file-based AV signatures

---

## Multi-Stage Payload Delivery

### Observation

The initial AES payload decrypts additional AES payloads.

### Advantages

- Layered defense evasion
- Payload replacement flexibility
- Smaller initial stager

---

## HTTP-Based Delivery

### Observation

PowerShell dynamically creates web requests.

### Expected Next Steps

Potential retrieval of:

- PowerShell scripts
- DLL files
- EXE payloads
- Configuration files
- Shellcode

---

# Threat Assessment

## Risk Level

```text
HIGH
```

## Reasoning

The sample demonstrates:

✅ Encryption

✅ Runtime decryption

✅ PowerShell execution

✅ Dynamic code execution

✅ String obfuscation

✅ Sleep-based evasion

✅ Network communication functionality

✅ Multi-stage architecture

These behaviors are strongly aligned with malware delivery frameworks.

---

# MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|------------|-----------|
| PowerShell | T1059.001 |
| Command and Scripting Interpreter | T1059 |
| Obfuscated Files or Information | T1027 |
| Deobfuscate/Decode Files | T1140 |
| Encrypted Payloads | T1027.013 |
| Ingress Tool Transfer | T1105 |
| Dynamic Payload Execution | T1620 |

---

# Threat Hunting Opportunities

## PowerShell Analytics

Search for:

```text
AesManaged
CreateDecryptor
TransformFinalBlock
Invoke-Expression
FromBase64String
```

---

## Process Analytics

Look for:

```text
powershell.exe
pwsh.exe
```

launching:

```text
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
```

---

## Network Analytics

Search for outbound connections initiated by:

```text
powershell.exe
```

especially shortly after:

```powershell
Start-Sleep
```

execution.

---

# Detection Opportunities

## Sigma Keywords

```yaml
selection:
  CommandLine|contains:
    - "AesManaged"
    - "CreateDecryptor"
    - "TransformFinalBlock"
    - "Invoke-Expression"
    - "FromBase64String"
```

---

## Elastic KQL

```kql
process.name : "powershell.exe" and
process.command_line.text :
(
  "*AesManaged*" or
  "*CreateDecryptor*" or
  "*TransformFinalBlock*" or
  "*Invoke-Expression*"
)
```

---

# Investigation Recommendations

## Endpoint

Review:

- PowerShell Operational Logs
- Sysmon Events
- SentinelOne Telemetry
- Microsoft Defender Telemetry

### Important Event IDs

```text
4103
4104
1
3
7
11
22
```

---

## Network

Identify:

- Destination IPs
- URLs
- User-Agent values
- Downloaded payloads

---

## Memory Analysis

Capture memory from impacted endpoints if available.

Look for:

```text
Decrypted PowerShell
Downloaded Scripts
Injected Payloads
```

---

# Conclusion

The analyzed sample is a multi-stage AES-encrypted PowerShell loader utilizing runtime decryption, in-memory execution, delayed execution, string obfuscation, and HTTP download functionality.

The first stage decrypts and executes a second-stage PowerShell script which introduces additional encrypted payloads and web request functionality, indicating preparation for further payload retrieval and execution.

Given the observed behavior, the activity should be treated as malicious until proven otherwise. Additional decryption of the remaining embedded AES payloads would likely reveal the final objective, infrastructure, and payload delivery mechanism used by the actor.
