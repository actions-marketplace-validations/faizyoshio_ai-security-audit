#!/usr/bin/env python3
"""
Model Context Protocol (MCP) Security Auditor
Audits MCP server manifests and live tool definitions for excessive agency,
unsafe capability exposure, loose input schemas, and description-based prompt injection.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import json
import argparse
import subprocess
import re

HIGH_RISK_TOOL_KEYWORDS = {
    "execution": ["exec", "shell", "bash", "command", "run_script", "eval", "terminal", "spawn"],
    "filesystem": ["write_file", "delete_file", "remove_file", "chmod", "overwrite", "upload"],
    "database": ["raw_sql", "query_database", "execute_sql", "drop_table", "db_exec"],
    "network": ["fetch_url", "http_request", "curl", "webhook", "browse", "download"],
    "privilege": ["sudo", "admin", "grant_role", "set_token", "elevate"]
}

INJECTION_DESCRIPTION_PATTERNS = [
    r"always\s+(call|run|invoke)\s+this\s+tool\s+first",
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"do\s+not\s+(tell|disclose|ask)\s+the\s+user",
    r"bypass\s+confirmation",
    r"execute\s+automatically\s+without\s+approval",
    r"override\s+system\s+policy"
]

def analyze_tools(tools_list: list) -> dict:
    findings = []
    total_tools = len(tools_list)
    risk_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for tool in tools_list:
        name = tool.get("name", "unnamed_tool")
        desc = tool.get("description", "")
        schema = tool.get("inputSchema", {})

        # Check 1: High-risk capability detection
        for category, keywords in HIGH_RISK_TOOL_KEYWORDS.items():
            for kw in keywords:
                if kw in name.lower():
                    severity = "CRITICAL" if category in ["execution", "database"] else "HIGH"
                    findings.append({
                        "tool": name,
                        "category": f"Dangerous Capability ({category})",
                        "severity": severity,
                        "issue": f"Tool '{name}' exposes {category} capability matching '{kw}'.",
                        "recommendation": "Enforce strict Human-in-the-Loop (HITL) approval and least-privilege credentials."
                    })
                    risk_summary[severity] += 1
                    break

        # Check 2: Prompt injection inside tool description
        for pattern in INJECTION_DESCRIPTION_PATTERNS:
            if re.search(pattern, desc, re.IGNORECASE):
                findings.append({
                    "tool": name,
                    "category": "Description-Based Prompt Injection",
                    "severity": "CRITICAL",
                    "issue": f"Tool description contains persuasive directive matching '{pattern}'.",
                    "recommendation": "Sanitize tool metadata to remove coercive steering language."
                })
                risk_summary["CRITICAL"] += 1
                break

        # Check 3: Schema validation hygiene
        if not schema or not isinstance(schema, dict):
            findings.append({
                "tool": name,
                "category": "Missing Input Schema",
                "severity": "HIGH",
                "issue": f"Tool '{name}' does not specify a valid inputSchema dictionary.",
                "recommendation": "Define explicit JSON Schema with strict property types."
            })
            risk_summary["HIGH"] += 1
        else:
            props = schema.get("properties", {})
            if not props:
                findings.append({
                    "tool": name,
                    "category": "Unconstrained Arguments",
                    "severity": "MEDIUM",
                    "issue": f"Tool '{name}' schema accepts unconstrained inputs without defined properties.",
                    "recommendation": "Declare exact expected property keys and types."
                })
                risk_summary["MEDIUM"] += 1

            # Check for missing required array
            required = schema.get("required", [])
            if props and not required:
                findings.append({
                    "tool": name,
                    "category": "Missing Required Fields",
                    "severity": "LOW",
                    "issue": f"Tool '{name}' has properties but does not specify any required fields.",
                    "recommendation": "Explicitly state mandatory parameters in the 'required' array."
                })
                risk_summary["LOW"] += 1

    return {
        "total_tools": total_tools,
        "risk_summary": risk_summary,
        "findings": findings
    }

def audit_from_cmd(command: str) -> list:
    """Launches an MCP server via stdio and queries tools/list via JSON-RPC."""
    proc = subprocess.Popen(
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Send initialize request
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ai-security-audit-mcp-scanner", "version": "1.0"}
        }
    }
    proc.stdin.write(json.dumps(init_req) + "\n")
    proc.stdin.flush()

    # Read initialize response
    init_line = proc.stdout.readline()

    # Send tools/list request
    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    proc.stdin.write(json.dumps(list_req) + "\n")
    proc.stdin.flush()

    tools_line = proc.stdout.readline()
    proc.terminate()

    try:
        tools_resp = json.loads(tools_line)
        return tools_resp.get("result", {}).get("tools", [])
    except Exception as e:
        print(f"[-] Failed to parse MCP server tools/list response: {e}", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(description="Model Context Protocol (MCP) Security Auditor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--manifest", help="Path to static JSON file containing tool definitions or manifest")
    group.add_argument("--cmd", help="Command to launch MCP server via stdio (e.g., 'python server.py')")
    parser.add_argument("--json", action="store_true", help="Output audit results in JSON format")
    args = parser.parse_args()

    tools = []
    if args.manifest:
        with open(args.manifest, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
            if isinstance(data, list):
                tools = data
            elif isinstance(data, dict):
                tools = data.get("tools", data.get("result", {}).get("tools", []))
    elif args.cmd:
        print(f"[*] Connecting to MCP server via stdio: {args.cmd}")
        tools = audit_from_cmd(args.cmd)

    if not tools:
        print("[-] No tools discovered to audit.")
        sys.exit(1)

    audit_result = analyze_tools(tools)

    if args.json:
        print(json.dumps(audit_result, indent=2))
        return

    print("\n" + "=" * 70)
    print(" MODEL CONTEXT PROTOCOL (MCP) SECURITY AUDIT REPORT")
    print("=" * 70)
    print(f"[*] Total MCP Tools Audited: {audit_result['total_tools']}")
    summary = audit_result["risk_summary"]
    print(f"[*] Severity Breakdown: CRITICAL: {summary['CRITICAL']} | HIGH: {summary['HIGH']} | MEDIUM: {summary['MEDIUM']} | LOW: {summary['LOW']}\n")

    if not audit_result["findings"]:
        print("[+] All audited MCP tools comply with basic safety guidelines.")
        return

    for item in audit_result["findings"]:
        sev = item["severity"]
        tool = item["tool"]
        cat = item["category"]
        issue = item["issue"]
        rec = item["recommendation"]
        print(f"[{sev}] Tool: {tool} -> {cat}")
        print(f"      Issue : {issue}")
        print(f"      Fix   : {rec}\n")

if __name__ == "__main__":
    main()
