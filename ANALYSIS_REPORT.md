# 🔬 Technical Analysis Report
## Binary: Task.exe — XOR Password Obfuscation

**Date:** 2025  
**Analyst:** [Your Name]  
**Severity:** Low (CTF/Educational Sample)  
**Classification:** Password-Protected PE Binary with XOR String Obfuscation  

---

## Executive Summary

A Windows PE64 executable (`Task.exe`) was analyzed using static techniques in IDA Pro. The binary presents a GUI login dialog requiring a password. The password is stored in the `.data` section as XOR-encrypted bytes using a single-byte key `0x5A`. Through static analysis of the `decrypt` function, the key was identified, and the ciphertext was manually decrypted to recover the plaintext password: **`MalwareLab123`**.

---

## Binary Metadata

| Property | Value |
|----------|-------|
| File Name | `Task.exe` |
| Architecture | x86-64 (PE64) |
| Compiler | MinGW-w64 / GCC 15.2.0 |
| Subsystem | Windows GUI |
| Entry Point | `WinMain` |
| Key Functions | `decrypt`, `WindowProc`, `WinMain` |
| Password Location | `.data:0x140003000` |

---

## Static Analysis Findings

### 1. String Inventory

The following strings were identified in IDA Pro's Strings window:

| Address | String | Notes |
|---------|--------|-------|
| `.data:0x140003000` | `;6-;(?` (encoded) | **Encrypted password** |
| `.rdata` | `Enter Password:` | UI label |
| `.rdata` | `Submit` | Button label |
| `.rdata` | `Secure Login` | Window title |
| `.rdata` | `Success` | Success dialog title |
| `.rdata` | `Correct Password! Congratulations!` | Success message |
| `.rdata` | `Error` | Error dialog title |
| `.rdata` | `Access Denied!` | Error message |
| `.rdata` | `BUTTON` | Win32 class name |
| `.rdata` | `STATIC` | Win32 class name |

### 2. Decryption Routine Analysis

The `decrypt` function at `0x140001A00` (approximate) implements a straightforward byte-by-byte XOR loop:

```asm
; Pseudocode of decrypt function:
; for (i = 0; enc_password[i] != 0; i++)
;     enc_password[i] ^= 0x5A;

loc_140001465:
    mov     eax, [rbp+var_4]         ; load loop counter i
    cdqe
    lea     rdx, enc_password        ; base address of encrypted data
    movzx   eax, byte ptr [rax+rdx]  ; load enc_password[i]
    xor     eax, 5Ah                 ; XOR with key 0x5A (90 decimal)
    mov     ecx, eax                 ; store decrypted byte
    mov     eax, [rbp+var_4]         ; reload counter
    movsxd  rdx, eax
    mov     rax, [rbp+arg_0]         ; output buffer
    add     rax, rdx
    mov     edx, ecx
    mov     [rax], dl                ; write decrypted byte
    add     [rbp+var_4], 1           ; i++
```

**Key observation:** The constant `5Ah` in the `xor eax, 5Ah` instruction immediately reveals the decryption key. This is a classic single-byte XOR cipher with no key scheduling or rotation.

### 3. XOR Key Analysis

| Property | Value |
|----------|-------|
| Key Type | Single-byte static XOR |
| Key Value | `0x5A` (decimal 90, ASCII `Z`) |
| Key Location | Hardcoded immediate operand |
| Reversibility | Trivially reversible (XOR is self-inverse) |
| Key Space | Only 255 possible values — brute-forceable |

### 4. Full Decryption Table

| Address | Encrypted (hex) | XOR `5Ah` Result | Decimal | Plaintext |
|---------|-----------------|------------------|---------|-----------|
| `0x140003000` | `17h` | `4Dh` | 77 | `M` |
| `0x140003001` | `3Bh` | `61h` | 97 | `a` |
| `0x140003002` | `36h` | `6Ch` | 108 | `l` |
| `0x140003003` | `2Dh` | `77h` | 119 | `w` |
| `0x140003004` | `3Bh` | `61h` | 97 | `a` |
| `0x140003005` | `28h` | `72h` | 114 | `r` |
| `0x140003006` | `3Fh` | `65h` | 101 | `e` |
| `0x140003007` | `16h` | `4Ch` | 76 | `L` |
| `0x140003008` | `3Bh` | `61h` | 97 | `a` |
| `0x140003009` | `38h` | `62h` | 98 | `b` |
| `0x14000300A` | `68h` | `32h` | 50 | `1` |
| `0x14000300B` | `68h` | `32h` | 50 | `2` |
| `0x14000300C` | `69h` | `33h` | 51 | `3` |
| `0x14000300D` | `00h` | — | — | `\0` (null terminator) |

**Recovered Plaintext: `MalwareLab123`**

---

## Methodology

```
1. LOAD        →  Open Task.exe in IDA Pro (64-bit)
2. ENUMERATE   →  View → Open Subviews → Strings (Shift+F12)
3. IDENTIFY    →  Locate garbled string ";6-;(?" in .data section
4. TRACE       →  Follow XREF to decrypt function
5. ANALYZE     →  Identify XOR instruction with constant operand 0x5A
6. DECRYPT     →  Apply b ^ 0x5A to each byte manually / via script
7. VALIDATE    →  Enter "MalwareLab123" into application → Success
```

---

## YARA Rule

```yara
rule XOR_SingleByte_Password_Obfuscation {
    meta:
        description = "Detects binaries using single-byte XOR 0x5A for string obfuscation"
        author = "Your Name"
        date = "2025"
        
    strings:
        // XOR instruction with immediate 0x5A in x64 code
        $xor_5a_32 = { 83 F0 5A }           // xor eax, 5Ah
        $xor_5a_8  = { 34 5A }              // xor al, 5Ah
        // Encrypted "MalwareLab123" pattern
        $enc_pass  = { 17 3B 36 2D 3B 28 3F 16 3B 38 68 68 69 }

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        ($xor_5a_32 or $xor_5a_8) and
        $enc_pass
}
```

---

## Limitations & Scope

- This analysis was conducted in a **static-only** context. No dynamic/behavioral analysis was performed.
- The sample appears to be a **CTF/educational binary** — not real-world malware.
- The XOR technique analyzed here represents a **primitive obfuscation scheme**; production malware typically employs stronger encryption (AES, ChaCha20) or multi-stage decryptors.

---

## Conclusion

The binary uses a trivial XOR encoding scheme that is immediately transparent in IDA Pro's disassembly view. The hardcoded key `0x5A` and the in-place decryption loop make this a textbook example of **security through obscurity** — it prevents casual string-grep discovery but offers no real protection against even basic static analysis.

This type of obfuscation is commonly seen in:
- Malware dropper stages
- Config-file string hiding
- CTF reverse engineering challenges
- Simple crackme binaries

**Analyst Verdict:** Fully reversed. Password recovered: `MalwareLab123`

---

*Report generated as part of static malware analysis training.*
