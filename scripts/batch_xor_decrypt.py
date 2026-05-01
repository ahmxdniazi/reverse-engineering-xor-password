#!/usr/bin/env python3
"""
batch_xor_decrypt.py
====================
Batch XOR Decryption Tool — processes multiple encrypted strings
extracted from IDA Pro analysis.

This script demonstrates how to automate decryption of multiple
XOR-obfuscated strings found during static malware analysis.
"""

# All encrypted byte sequences found in Task.exe .data section
# Each entry: (address, description, encrypted_bytes)
ENCRYPTED_STRINGS = [
    (
        0x140003000,
        "enc_password",
        [0x17, 0x3B, 0x36, 0x2D, 0x3B, 0x28, 0x3F, 0x16, 0x3B, 0x38, 0x68, 0x68, 0x69]
    ),
    # Additional encrypted strings can be added here as analysis continues
    # (0x140003010, "enc_string_2", [...]),
]

XOR_KEY = 0x5A


def decrypt_string(encrypted: list[int], key: int) -> str:
    return ''.join(chr(b ^ key) for b in encrypted)


def main():
    print("\n" + "="*60)
    print("  BATCH XOR DECRYPTION RESULTS")
    print(f"  Key: 0x{XOR_KEY:02X} | Source: Task.exe static analysis")
    print("="*60)

    for addr, name, enc_bytes in ENCRYPTED_STRINGS:
        decrypted = decrypt_string(enc_bytes, XOR_KEY)
        print(f"\n  Address  : {hex(addr)}")
        print(f"  Label    : {name}")
        print(f"  Encrypted: {' '.join(f'{b:02X}' for b in enc_bytes)}")
        print(f"  Plaintext: \033[92m{decrypted}\033[0m")

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
