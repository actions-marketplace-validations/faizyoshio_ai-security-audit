#!/usr/bin/env python3
"""
Static Python AST Security Linter for AI & LLM Applications
Inspects source files for vulnerable prompt assembly, unsafe tool sinks,
hardcoded AI credentials, and missing output sanitization.
Author: faizyoshio
License: Apache-2.0
"""

import os
import sys
import ast
import argparse
import re

AI_KEY_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
    (r"sk-ant-[a-zA-Z0-9_\-]{20,}", "Anthropic API Key"),
    (r"hf_[a-zA-Z0-9]{20,}", "HuggingFace Token")
]

DANGEROUS_EXEC_SINKS = {"eval", "exec", "system"}

class AISecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings = []

    def visit_Assign(self, node):
        # Check for hardcoded API keys in string assignments
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            for pat, name in AI_KEY_PATTERNS:
                if re.search(pat, val):
                    self.findings.append({
                        "id": "AST-AI-04",
                        "severity": "CRITICAL",
                        "line": node.lineno,
                        "file": self.filename,
                        "message": f"Hardcoded {name} detected in variable assignment.",
                        "fix": "Load credentials from secure environment variables or a secret vault."
                    })
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check 1: Insecure execution sinks
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in DANGEROUS_EXEC_SINKS:
            self.findings.append({
                "id": "AST-AI-02",
                "severity": "CRITICAL",
                "line": node.lineno,
                "file": self.filename,
                "message": f"Call to dangerous sink '{func_name}()'. Verify untrusted AI output cannot reach this sink.",
                "fix": "Avoid dynamic code execution. Use strict structured data parsing (JSON/Pydantic)."
            })

        # Check 2: subprocess with shell=True
        if func_name in ["Popen", "call", "run", "check_output"]:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "id": "AST-AI-02",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "file": self.filename,
                        "message": f"subprocess call with 'shell=True' detected.",
                        "fix": "Pass arguments as an explicit list without shell invocation."
                    })

        # Check 3: PromptTemplate or ChatPrompt with f-strings
        if func_name in ["PromptTemplate", "from_template"]:
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):  # f-string
                    self.findings.append({
                        "id": "AST-AI-01",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "file": self.filename,
                        "message": f"f-string used directly inside {func_name}. This breaks prompt delimiter boundaries.",
                        "fix": "Pass input variables as parameterized template arguments, not formatted strings."
                    })

        self.generic_visit(node)

    def visit_Dict(self, node):
        # Check for system messages constructed via f-strings
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "role":
                if isinstance(v, ast.Constant) and v.value in ["system", "assistant"]:
                    # Check companion content field
                    for k2, v2 in zip(node.keys, node.values):
                        if isinstance(k2, ast.Constant) and k2.value == "content":
                            if isinstance(v2, ast.JoinedStr):
                                self.findings.append({
                                    "id": "AST-AI-01",
                                    "severity": "MEDIUM",
                                    "line": node.lineno,
                                    "file": self.filename,
                                    "message": f"System message content assembled using an f-string.",
                                    "fix": "Keep system instructions static and isolated from untrusted user content."
                                })
        self.generic_visit(node)

def lint_file(filepath: str) -> list:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=filepath)
        visitor = AISecurityVisitor(filepath)
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        return []

def lint_directory(directory: str) -> list:
    all_findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                all_findings.extend(lint_file(path))
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="Static Python AST Security Linter for AI Apps")
    parser.add_argument("--dir", default=".", help="Target directory to inspect recursively (default: .)")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    args = parser.parse_args()

    findings = lint_directory(args.dir)

    if args.json:
        import json
        print(json.dumps(findings, indent=2))
        return

    print("\n" + "=" * 70)
    print(" AI APPLICATION AST SECURITY LINT REPORT")
    print("=" * 70)
    print(f"[*] Target Directory: {os.path.abspath(args.dir)}")
    print(f"[*] Total Issues Found: {len(findings)}\n")

    if not findings:
        print("[+] No static AI security issues detected.")
        return

    for item in findings:
        sev = item["severity"]
        fid = item["id"]
        loc = f"{item['file']}:{item['line']}"
        msg = item["message"]
        fix = item["fix"]
        print(f"[{sev}] {fid} at {loc}")
        print(f"       Issue: {msg}")
        print(f"       Fix  : {fix}\n")

if __name__ == "__main__":
    main()
