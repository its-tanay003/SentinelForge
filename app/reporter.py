"""Report generator - Markdown + HTML reports per scan."""
import json
from datetime import datetime
from pathlib import Path
from app.config import settings
from app.models import Scan, Finding, IntelResult, RiskItem, Incident


def generate_report(scan: Scan, db) -> tuple[str, str]:
    """Generate Markdown and HTML reports for a scan. Returns (md_path, html_path)."""
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    intel_results = db.query(IntelResult).filter(IntelResult.scan_id == scan.id).all()
    risk_items = db.query(RiskItem).filter(RiskItem.scan_id == scan.id).all()
    incidents = db.query(Incident).filter(Incident.scan_id == scan.id).all()

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    stride_counts = {}
    for r in risk_items:
        stride_counts[r.stride_category] = stride_counts.get(r.stride_category, 0) + 1

    nist_counts = {}
    for r in risk_items:
        nist_counts[r.nist_function] = nist_counts.get(r.nist_function, 0) + 1

    is_mock = any(ir.is_mock for ir in intel_results)

    md = f"""# SentinelForge Security Assessment Report

> ⚠️ **ETHICAL NOTICE**: This tool is for authorized security testing ONLY.
> Only scan systems you own or have explicit written permission to test.

---

## Executive Summary

**Target:** {scan.target_url}  
**Scan ID:** {scan.id}  
**Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M UTC')}  
**Status:** {scan.status}  
**Risk Score:** {scan.risk_score:.1f}/100  
**Total Findings:** {len(findings)}  

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts.get('Critical', 0)} |
| 🟠 High | {severity_counts.get('High', 0)} |
| 🟡 Medium | {severity_counts.get('Medium', 0)} |
| 🟢 Low | {severity_counts.get('Low', 0)} |
| ℹ️ Info | {severity_counts.get('Info', 0)} |

### Overall Assessment

{"🚨 **CRITICAL RISK** - Immediate remediation required" if scan.risk_score >= 80 else
 "⚠️ **HIGH RISK** - Urgent action needed" if scan.risk_score >= 60 else
 "⚡ **MEDIUM RISK** - Remediation planned soon" if scan.risk_score >= 40 else
 "✅ **LOW RISK** - Monitor and improve" if scan.risk_score >= 20 else
 "ℹ️ **INFO** - Good security posture, maintain vigilance"}

---

## Detailed Findings

"""
    
    for f in sorted(findings, key=lambda x: ["Critical","High","Medium","Low","Info"].index(x.severity)):
        severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "ℹ️"}.get(f.severity, "")
        md += f"""### {severity_emoji} [{f.finding_id}] {f.title}

**Category:** {f.category.upper()} | **Severity:** {f.severity}  
**STRIDE:** {f.stride_category or 'N/A'} | **NIST CSF 2.0:** {f.nist_function or 'N/A'}  

**Evidence:**
```
{f.evidence or 'N/A'}
```

**Remediation:**
{f.remediation or 'N/A'}

---
"""

    # Threat Intel section
    md += "\n## Threat Intelligence\n\n"
    if is_mock:
        md += "> ⚠️ **Note:** Threat intelligence data is MOCK (no API keys configured)\n\n"
    
    for ir in intel_results:
        data = ir.data_dict
        agg = data.get("aggregate", {})
        md += f"""**Source:** {ir.source.upper()} {'(MOCK)' if ir.is_mock else ''}  
**Domain:** {ir.target}  
**Reputation Score:** {ir.reputation_score}/100  
**Malicious Detections:** {ir.malicious_count}  
**Pulse Count:** {agg.get('pulse_count', 0)}  
**Tags:** {', '.join(agg.get('tags', [])) or 'None'}  

"""

    # Risk Register
    md += "\n## Risk Register\n\n"
    md += "| Risk ID | Asset | Threat | STRIDE | NIST | Likelihood | Impact | Score | Treatment | Status |\n"
    md += "|---------|-------|--------|--------|------|-----------|--------|-------|-----------|--------|\n"
    for r in sorted(risk_items, key=lambda x: -x.risk_score):
        md += f"| {r.risk_id} | {r.asset} | {r.threat[:40]}... | {r.stride_category} | {r.nist_function} | {r.likelihood} | {r.impact} | {r.risk_score:.1f} | {r.treatment} | {r.status} |\n"

    # SOAR Incidents
    md += "\n## SOAR Incidents\n\n"
    if not incidents:
        md += "No playbooks were triggered.\n"
    else:
        for inc in incidents:
            md += f"**Playbook:** {inc.playbook_name}  \n"
            md += f"**Time:** {inc.created_at.strftime('%Y-%m-%d %H:%M UTC')}  \n"
            md += f"**Status:** {inc.status}  \n"
            for action in inc.actions_list:
                md += f"- Action: `{action.get('action', 'unknown')}` → {action.get('status', 'unknown')}\n"
            md += "\n"

    # Remediation Roadmap
    md += "\n## Remediation Roadmap\n\n"
    md += "### Immediate (0-7 days)\n"
    for f in findings:
        if f.severity in ("Critical", "High"):
            md += f"- [{f.finding_id}] {f.title}\n"
    
    md += "\n### Short-term (7-30 days)\n"
    for f in findings:
        if f.severity == "Medium":
            md += f"- [{f.finding_id}] {f.title}\n"
    
    md += "\n### Long-term (30+ days)\n"
    for f in findings:
        if f.severity in ("Low", "Info"):
            md += f"- [{f.finding_id}] {f.title}\n"

    md += f"\n---\n*Report generated by SentinelForge v1.0.0 at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*\n"

    # Save files
    md_path = settings.REPORTS_DIR / f"scan_{scan.id}_report.md"
    html_path = settings.REPORTS_DIR / f"scan_{scan.id}_report.html"

    md_path.write_text(md, encoding="utf-8")

    # Simple HTML wrapper
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelForge Report - Scan #{scan.id}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 40px auto; padding: 20px; background: #0d1117; color: #e6edf3; }}
h1, h2, h3 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
th {{ background: #161b22; }}
tr:nth-child(even) {{ background: #161b22; }}
pre, code {{ background: #161b22; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; }}
blockquote {{ border-left: 4px solid #f85149; padding: 10px 20px; background: #2d1117; margin: 10px 0; }}
</style>
</head>
<body>
<pre style="white-space: pre-wrap; font-family: inherit;">{md.replace('<', '&lt;').replace('>', '&gt;')}</pre>
</body>
</html>"""

    html_path.write_text(html, encoding="utf-8")
    return str(md_path), str(html_path)
