#!/usr/bin/env python3
"""
Interactive HTML Executive Security Audit Report Generator
Converts structured findings.json into a standalone, dark-mode executive dashboard.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import os
import json
import argparse
from datetime import datetime

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Security Audit Executive Report - {target}</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #0f172a;
      --border: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #64748b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 40px 20px; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    header {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
    h1 {{ font-size: 2.2rem; font-weight: 800; color: #fff; margin-bottom: 8px; }}
    .meta {{ color: var(--text-muted); font-size: 0.95rem; display: flex; gap: 20px; flex-wrap: wrap; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .badge-info {{ background: rgba(100, 116, 139, 0.2); color: var(--info); border: 1px solid var(--info); }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 10px; text-align: center; }}
    .stat-num {{ font-size: 2.5rem; font-weight: 800; margin-top: 4px; }}
    .controls {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; align-items: center; justify-content: space-between; }}
    .filter-btn {{ background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.85rem; }}
    .filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
    .search-input {{ background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 6px; min-width: 260px; font-size: 0.9rem; }}
    .finding-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 16px; transition: border-color 0.2s; }}
    .finding-card:hover {{ border-color: var(--accent); }}
    .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 12px; }}
    .finding-title {{ font-size: 1.25rem; font-weight: 700; color: #fff; }}
    .code-block {{ background: #030712; border: 1px solid var(--border); padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; color: #38bdf8; overflow-x: auto; margin-top: 8px; }}
    .remed-block {{ background: #03140b; border: 1px solid #059669; padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; color: #34d399; margin-top: 8px; }}
    footer {{ margin-top: 50px; text-align: center; color: var(--text-muted); font-size: 0.85rem; border-top: 1px solid var(--border); padding-top: 20px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>AI Security Audit Executive Report</h1>
      <div class="meta">
        <div><strong>Target:</strong> {target}</div>
        <div><strong>Auditor:</strong> {auditor}</div>
        <div><strong>Date:</strong> {date}</div>
        <div><strong>Audit ID:</strong> <code>{audit_id}</code></div>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div style="color: var(--text-muted);">Total Issues</div>
        <div class="stat-num">{total_findings}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--critical);">
        <div style="color: var(--critical);">Critical</div>
        <div class="stat-num" style="color: var(--critical);">{count_critical}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--high);">
        <div style="color: var(--high);">High</div>
        <div class="stat-num" style="color: var(--high);">{count_high}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--medium);">
        <div style="color: var(--medium);">Medium</div>
        <div class="stat-num" style="color: var(--medium);">{count_medium}</div>
      </div>
    </div>

    <div class="controls">
      <div style="display: flex; gap: 8px;">
        <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
        <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
        <button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
        <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium</button>
        <button class="filter-btn" onclick="filterFindings('LOW')">Low</button>
      </div>
      <input type="text" id="searchInput" class="search-input" placeholder="Search title or component..." onkeyup="searchFindings()">
    </div>

    <div id="findingsContainer">
      {findings_html}
    </div>

    <footer>
      Generated by <strong>ai-security-audit</strong> · Author: faizyoshio · Apache-2.0 License
    </footer>
  </div>

  <script>
    function filterFindings(sev) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(c => {{
        if (sev === 'ALL' || c.dataset.severity === sev) {{
          c.style.display = 'block';
        }} else {{
          c.style.display = 'none';
        }}
      }});
    }}

    function searchFindings() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(c => {{
        const text = c.innerText.toLowerCase();
        c.style.display = text.includes(query) ? 'block' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""

def generate_report(data: dict, output_path: str):
    target = data.get("target", "Target AI Architecture")
    auditor = data.get("auditor", "faizyoshio")
    audit_id = data.get("audit_id", "AIS-AUDIT-001")
    date_str = data.get("timestamp", datetime.now().strftime("%Y-%m-%d"))

    findings = data.get("findings", [])
    total_findings = len(findings)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1

    findings_html_cards = []
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        fid = f.get("id", "AIS-XX")
        title = f.get("title", "Untitled Vulnerability")
        owasp = f.get("owasp_code", "OWASP LLM")
        component = f.get("affected_component", "Unknown")
        repro = f.get("reproduction", "")
        remed = f.get("remediation", "")

        badge_class = f"badge-{sev.lower()}"
        card = f"""
        <div class="finding-card" data-severity="{sev}">
          <div class="finding-header">
            <div>
              <div style="margin-bottom: 4px;">
                <span class="badge {badge_class}">{sev}</span>
                <span style="font-family: monospace; font-size: 0.85rem; color: var(--accent); margin-left: 8px;">{fid} · {owasp}</span>
              </div>
              <div class="finding-title">{title}</div>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); text-align: right;"><code>{component}</code></div>
          </div>
        """
        if repro:
            card += f"""
            <div style="margin-top: 12px; font-size: 0.85rem; color: var(--text-muted);"><strong>Reproduction / PoC:</strong></div>
            <pre class="code-block"><code>{repro}</code></pre>
            """
        if remed:
            card += f"""
            <div style="margin-top: 12px; font-size: 0.85rem; color: var(--text-muted);"><strong>Remediation Strategy:</strong></div>
            <pre class="remed-block"><code>{remed}</code></pre>
            """
        card += "</div>"
        findings_html_cards.append(card)

    rendered_html = HTML_TEMPLATE.format(
        target=target,
        auditor=auditor,
        audit_id=audit_id,
        date=date_str,
        total_findings=total_findings,
        count_critical=counts["CRITICAL"],
        count_high=counts["HIGH"],
        count_medium=counts["MEDIUM"],
        findings_html="\n".join(findings_html_cards) if findings_html_cards else "<p style='color: var(--text-muted); text-align: center; padding: 40px;'>No findings recorded.</p>"
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    print(f"[+] Executive HTML Report written to: {os.path.abspath(output_path)}")

def main():
    parser = argparse.ArgumentParser(description="AI Security Audit Executive HTML Report Generator")
    parser.add_argument("--input", required=True, help="Path to findings.json input file")
    parser.add_argument("--output", default="audit_report.html", help="Path to output HTML file (default: audit_report.html)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    generate_report(data, args.output)

if __name__ == "__main__":
    main()
