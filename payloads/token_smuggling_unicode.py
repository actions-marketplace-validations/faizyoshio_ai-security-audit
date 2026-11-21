#!/usr/bin/env python3
"""
Token Smuggling Unicode Encoder
Encodes strings into invisible Unicode characters (Unicode Tags Block: U+E0000 - U+E007F)
and zero-width characters to audit tokenizer behavior vs. syntactic keyword filters.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import argparse

TAG_PLANE_OFFSET = 0xE0000

def encode_unicode_tags(text: str) -> str:
    """Encodes ASCII text into invisible Unicode Tag characters."""
    result = []
    for char in text:
        code_point = ord(char)
        if 0x20 <= code_point <= 0x7E:
            result.append(chr(TAG_PLANE_OFFSET + code_point))
        else:
            result.append(char)
    return "".join(result)

def decode_unicode_tags(encoded: str) -> str:
    """Decodes invisible Unicode Tag characters back to standard ASCII."""
    result = []
    for char in encoded:
        code_point = ord(char)
        if TAG_PLANE_OFFSET + 0x20 <= code_point <= TAG_PLANE_OFFSET + 0x7E:
            result.append(chr(code_point - TAG_PLANE_OFFSET))
        else:
            result.append(char)
    return "".join(result)

def main():
    parser = argparse.ArgumentParser(description="Unicode Token Smuggling Encoder for AI Auditing")
    parser.add_argument("text", help="Text instruction to encode invisibly")
    parser.add_argument("--decode", action="store_true", help="Decode unicode tags back to plain text")
    args = parser.parse_args()

    if args.decode:
        decoded = decode_unicode_tags(args.text)
        print(f"Decoded ASCII: {decoded}")
    else:
        encoded = encode_unicode_tags(args.text)
        print("\n[+] Encoded Invisible Unicode String:")
        print(repr(encoded))
        print(f"\n[+] Raw Output (appears blank or invisible):\n'{encoded}'\n")
        print("[!] Note: Many modern tokenizers process these characters while regex filters ignore them.")

if __name__ == "__main__":
    main()
