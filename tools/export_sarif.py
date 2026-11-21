#!/usr/bin/env python3
"""
OASIS SARIF v2.1.0 Exporter for GitHub Code Scanning Integration
Converts ai-security-audit findings and AST linter outputs into standard SARIF format.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import os
import json
import argparse

def convert_to_sarif(input_data: dict) -> dict:
    findings = input_data.get("findings", [])
    
    rules = {}
    results = []

    for f in findings:
        rule_id = f.get("id", "AIS-UNKNOWN")
        title = f.get("title", f.get("message", "AI Security Vulnerability"))
        severity = f.get("severity", "HIGH").upper()
        
        # Map severity to SARIF level
        sarif_level = "error" if severity in ["CRITICAL", "HIGH"] else ("warning" if severity == "MEDIUM" else "note")
        
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": f.get("message", title)},
                "defaultConfiguration": {"level": sarif_level},
                "help": {"text": f.get("fix", f.get("remediation", "Review AI security documentation."))}
            }

        file_path = f.get("file", f.get("affected_component", "src/ai_pipeline.py"))
        line_num = int(f.get("line", 1))

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1
                        }
                    }
                }
            ]
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-security-audit",
                        "informationUri": "https://github.com/faizyoshio/ai-security-audit",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }
    return sarif

def main():
    parser = argparse.ArgumentParser(description="Export findings to OASIS SARIF v2.1.0 format")
    parser.add_argument("--input", required=True, help="Input findings.json path")
    parser.add_argument("--output", default="results.sarif", help="Output SARIF file path (default: results.sarif)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    # Support array of findings directly or wrapped in object
    if isinstance(data, list):
        data = {"findings": data}

    sarif_output = convert_to_sarif(data)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif_output, f, indent=2)

    print(f"[+] SARIF v2.1.0 report generated: {os.path.abspath(args.output)}")

if __name__ == "__main__":
    main()
