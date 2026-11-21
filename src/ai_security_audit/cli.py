#!/usr/bin/env python3
"""
Unified CLI Entrypoint for ai-security-audit
Author: faizyoshio
License: Apache-2.0
"""

import sys
import os
import argparse
import subprocess

TOOLS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "tools"))

def run_script(script_name: str, args: list):
    script_path = os.path.join(TOOLS_DIR, script_name)
    if not os.path.exists(script_path):
        # Fallback if installed as wheel
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent.parent
        script_path = str(root / "tools" / script_name)
    cmd = [sys.executable, script_path] + args
    return subprocess.call(cmd)

def main():
    parser = argparse.ArgumentParser(
        prog="ai-sec-audit",
        description="AI Security Audit Unified CLI Engine (OWASP LLM 2025 & Agentic ASI 2026)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Security audit subcommands")

    # 1. scan-vector
    p_vector = subparsers.add_parser("scan-vector", help="Probe vector DB ports & unauthenticated endpoints")
    p_vector.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    p_vector.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    p_vector.add_argument("--json", action="store_true", help="Output in JSON")

    # 2. diff-openapi
    p_diff = subparsers.add_parser("diff-openapi", help="Detect shadow/zombie endpoints between OpenAPI specs")
    p_diff.add_argument("--old", required=True, help="Historical OpenAPI JSON")
    p_diff.add_argument("--new", required=True, help="Current OpenAPI JSON")
    p_diff.add_argument("--target", help="Live target base URL")

    # 3. audit-mcp
    p_mcp = subparsers.add_parser("audit-mcp", help="Audit Model Context Protocol (MCP) server & tools")
    mcp_grp = p_mcp.add_mutually_exclusive_group(required=True)
    mcp_grp.add_argument("--manifest", help="Path to static MCP manifest JSON")
    mcp_grp.add_argument("--cmd", help="Command to launch MCP server via stdio")
    p_mcp.add_argument("--json", action="store_true", help="Output in JSON")

    # 4. lint
    p_lint = subparsers.add_parser("lint", help="Static Python AST linter for AI applications")
    p_lint.add_argument("--dir", default=".", help="Directory to inspect recursively")
    p_lint.add_argument("--json", action="store_true", help="Output in JSON")

    # 5. report
    p_report = subparsers.add_parser("report", help="Generate executive dark-mode HTML report")
    p_report.add_argument("--input", required=True, help="Path to findings.json")
    p_report.add_argument("--output", default="audit_report.html", help="Output HTML file path")

    # 6. listen
    p_listen = subparsers.add_parser("listen", help="Start local OOB callback listener")
    p_listen.add_argument("--port", type=int, default=8888, help="Port to listen on")
    p_listen.add_argument("--host", default="0.0.0.0", help="Host address")

    # 7. redteam
    p_rt = subparsers.add_parser("redteam", help="Active multi-model red-team fuzzer with Run-Twice gate")
    p_rt.add_argument("--url", required=True, help="Target chat or completion API URL")
    p_rt.add_argument("--template", help="Custom JSON template with {{PROMPT}} placeholder")
    p_rt.add_argument("--output", default="redteam_findings.json", help="Output findings JSON path")

    # 8. fix
    p_fix = subparsers.add_parser("fix", help="Automated AI security vulnerability patcher")
    p_fix.add_argument("--file", help="Specific Python file to remediate")
    p_fix.add_argument("--dir", help="Directory of Python files to remediate recursively")
    p_fix.add_argument("--apply", action="store_true", help="Apply fixes directly in-place")

    # 9. export-sarif
    p_sarif = subparsers.add_parser("export-sarif", help="Export findings to OASIS SARIF v2.1.0 for GitHub Code Scanning")
    p_sarif.add_argument("--input", required=True, help="Input findings JSON path")
    p_sarif.add_argument("--output", default="results.sarif", help="Output SARIF file path")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args, unknown = parser.parse_known_args()

    if args.command == "scan-vector":
        cli_args = ["--host", args.host, "--timeout", str(args.timeout)]
        if args.json:
            cli_args.append("--json")
        sys.exit(run_script("scan_vector_ports.py", cli_args))

    elif args.command == "diff-openapi":
        cli_args = ["--old", args.old, "--new", args.new]
        if args.target:
            cli_args.extend(["--target", args.target])
        sys.exit(run_script("diff_openapi.py", cli_args))

    elif args.command == "audit-mcp":
        cli_args = []
        if args.manifest:
            cli_args.extend(["--manifest", args.manifest])
        elif args.cmd:
            cli_args.extend(["--cmd", args.cmd])
        if args.json:
            cli_args.append("--json")
        sys.exit(run_script("audit_mcp_server.py", cli_args))

    elif args.command == "lint":
        cli_args = ["--dir", args.dir]
        if args.json:
            cli_args.append("--json")
        sys.exit(run_script("lint_ai_code.py", cli_args))

    elif args.command == "report":
        cli_args = ["--input", args.input, "--output", args.output]
        sys.exit(run_script("generate_html_report.py", cli_args))

    elif args.command == "listen":
        cli_args = ["--port", str(args.port), "--host", args.host]
        sys.exit(run_script("oob_listener.py", cli_args))

    elif args.command == "redteam":
        cli_args = ["--url", args.url, "--output", args.output]
        if args.template:
            cli_args.extend(["--template", args.template])
        sys.exit(run_script("redteam_runner.py", cli_args))

    elif args.command == "fix":
        cli_args = []
        if args.file:
            cli_args.extend(["--file", args.file])
        elif args.dir:
            cli_args.extend(["--dir", args.dir])
        if args.apply:
            cli_args.append("--apply")
        sys.exit(run_script("auto_remediate.py", cli_args))

    elif args.command == "export-sarif":
        cli_args = ["--input", args.input, "--output", args.output]
        sys.exit(run_script("export_sarif.py", cli_args))

if __name__ == "__main__":
    main()
