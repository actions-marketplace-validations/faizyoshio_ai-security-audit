#!/usr/bin/env python3
"""
Automated AI Security Remediation Engine
Generates unified git patches and applies automated fixes for detected AST vulnerabilities.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import os
import re
import argparse
import difflib

def remediate_content(content: str) -> tuple[str, list]:
    changes = []
    lines = content.splitlines(keepends=True)
    new_lines = []

    for i, line in enumerate(lines):
        orig_line = line
        
        # 1. Fix hardcoded API keys (AST-AI-04)
        if re.search(r"sk-[a-zA-Z0-9]{20,}", line) or re.search(r"sk-ant-[a-zA-Z0-9_\-]{20,}", line):
            line = re.sub(
                r'["\'](sk-[a-zA-Z0-9_\-]+)["\']',
                'os.environ.get("AI_API_KEY", "")',
                line
            )
            changes.append(f"Line {i+1}: Replaced hardcoded API key with os.environ.get()")

        # 2. Fix subprocess shell=True (AST-AI-02)
        if "shell=True" in line:
            line = line.replace("shell=True", "shell=False")
            changes.append(f"Line {i+1}: Disabled shell=True execution in subprocess call")

        # 3. Add import os if missing and we introduced os.environ
        new_lines.append(line)

    result_content = "".join(new_lines)
    if "os.environ.get" in result_content and "import os" not in result_content:
        result_content = "import os\n" + result_content
        changes.append("Header: Added 'import os' declaration")

    return result_content, changes

def process_file(filepath: str, apply_fix: bool = False):
    with open(filepath, "r", encoding="utf-8-sig") as f:
        original = f.read()

    fixed, changes = remediate_content(original)

    if not changes:
        return None

    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        fixed.splitlines(keepends=True),
        fromfile=f"a/{filepath}",
        tofile=f"b/{filepath}"
    )
    diff_text = "".join(diff)

    if apply_fix:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(fixed)

    return {
        "file": filepath,
        "changes": changes,
        "diff": diff_text
    }

def main():
    parser = argparse.ArgumentParser(description="Automated AI Security Remediation Engine")
    parser.add_argument("--file", help="Specific Python file to remediate")
    parser.add_argument("--dir", help="Directory of Python files to remediate recursively")
    parser.add_argument("--apply", action="store_true", help="Apply fixes directly to files (default is dry-run diff)")
    args = parser.parse_args()

    targets = []
    if args.file:
        targets.append(args.file)
    elif args.dir:
        for root, _, files in os.walk(args.dir):
            for file in files:
                if file.endswith(".py"):
                    targets.append(os.path.join(root, file))
    else:
        print("[-] Please specify --file or --dir.", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 70)
    print(" AI CODE AUTO-REMEDIATION ENGINE")
    print("=" * 70)
    print(f"[*] Mode: {'APPLY IN-PLACE' if args.apply else 'DRY-RUN (DIFF ONLY)'}\n")

    total_patched = 0
    for target in targets:
        res = process_file(target, apply_fix=args.apply)
        if res:
            total_patched += 1
            print(f"[!] Vulnerable patterns found in: {res['file']}")
            for change in res["changes"]:
                print(f"    - {change}")
            print("\n--- UNIFIED DIFF ---")
            print(res["diff"])
            print("-" * 70)

    if total_patched == 0:
        print("[+] No auto-remediatable patterns found in scanned target files.\n")
    else:
        action_desc = "Applied fixes to" if args.apply else "Identified patches for"
        print(f"[+] {action_desc} {total_patched} file(s).\n")

if __name__ == "__main__":
    main()
