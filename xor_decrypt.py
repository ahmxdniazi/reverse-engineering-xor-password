#!/usr/bin/env python3
"""
xor_decrypt.py
==============
XOR Single-Byte Decryption Tool
Reverse Engineering Companion Script

Target: Task.exe
Analysis Tool: IDA Pro
Technique: Single-byte XOR with key 0x5A

Usage:
    python xor_decrypt.py
    python xor_decrypt.py --key 0x5A --bytes "17 3B 36 2D 3B 28 3F 16 3B 38 68 68 69"
"""

import argparse
import sys


BANNER = """
╔══════════════════════════════════════════════════════════╗
║         XOR Single-Byte Decryption Tool                 ║
║         Reverse Engineering :: IDA Pro Analysis         ║
╚══════════════════════════════════════════════════════════╝
"""

# Encrypted bytes extracted from .data:0x140003000 (IDA Pro analysis)
ENCRYPTED_BYTES = [
    0x17, 0x3B, 0x36, 0x2D, 0x3B, 0x28, 0x3F,
    0x16, 0x3B, 0x38, 0x68, 0x68, 0x69
]

# XOR key discovered in decrypt() function: xor eax, 5Ah
XOR_KEY = 0x5A

BASE_ADDRESS = 0x140003000


def xor_decrypt(data: list[int], key: int) -> str:
    """Apply single-byte XOR decryption to a list of bytes."""
    return ''.join(chr(b ^ key) for b in data)


def print_table(data: list[int], key: int) -> None:
    """Print a formatted decryption table."""
    print(f"\n{'─'*65}")
    print(f"  {'Address':<16} {'Enc (hex)':<12} {'XOR Result':<12} {'Dec':<6} {'Char'}")
    print(f"{'─'*65}")
    
    for i, byte in enumerate(data):
        addr = BASE_ADDRESS + i
        result = byte ^ key
        char = chr(result) if 32 <= result <= 126 else '.'
        print(f"  {hex(addr):<16} {hex(byte):<12} {hex(result):<12} {result:<6} {char}")
    
    print(f"{'─'*65}\n")


def brute_force_xor(data: list[int], printable_threshold: float = 0.8) -> list[tuple]:
    """Try all single-byte XOR keys and return candidates with mostly printable chars."""
    candidates = []
    for key in range(1, 256):
        decrypted = [b ^ key for b in data]
        printable = sum(1 for b in decrypted if 32 <= b <= 126)
        ratio = printable / len(decrypted)
        if ratio >= printable_threshold:
            text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decrypted)
            candidates.append((key, ratio, text))
    return sorted(candidates, key=lambda x: x[1], reverse=True)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="XOR Single-Byte Decryption Tool for Reverse Engineering"
    )
    parser.add_argument(
        "--key", type=lambda x: int(x, 16), default=XOR_KEY,
        help="XOR key in hex (default: 0x5A)"
    )
    parser.add_argument(
        "--bytes", type=str, default=None,
        help='Space-separated hex bytes to decrypt (e.g. "17 3B 36")'
    )
    parser.add_argument(
        "--brute", action="store_true",
        help="Brute-force all 255 single-byte XOR keys"
    )
    args = parser.parse_args()

    # Use provided bytes or default encrypted bytes
    if args.bytes:
        try:
            data = [int(x, 16) for x in args.bytes.strip().split()]
        except ValueError:
            print("[!] Error: Invalid hex bytes provided.")
            sys.exit(1)
    else:
        data = ENCRYPTED_BYTES

    print(f"[*] Encrypted bytes ({len(data)}):")
    print(f"    {' '.join(f'{b:02X}h' for b in data)}\n")

    if args.brute:
        print("[*] Brute-forcing all single-byte XOR keys...\n")
        candidates = brute_force_xor(data)
        print(f"{'─'*55}")
        print(f"  {'Key':<8} {'Printable%':<14} {'Decrypted'}")
        print(f"{'─'*55}")
        for key, ratio, text in candidates[:10]:
            print(f"  0x{key:02X}     {ratio*100:>6.1f}%        {text}")
        print(f"{'─'*55}\n")
    else:
        key = args.key
        print(f"[*] Applying XOR with key: 0x{key:02X} (decimal {key})")
        print_table(data, key)
        result = xor_decrypt(data, key)
        print(f"[+] Decrypted password: \033[92m{result}\033[0m")
        print(f"[+] Length: {len(result)} characters\n")

        # Verify it's fully printable
        if all(32 <= ord(c) <= 126 for c in result):
            print("[✓] All characters are printable ASCII — decryption successful!\n")
        else:
            print("[!] Warning: Some non-printable characters found.\n")


if __name__ == "__main__":
    main()
