import os
import json

def main():
    output_path = "docs/THESIS_COMPARATIVE_ANALYSIS.html"
    ai_db_path = "all-results/accumulated_database.json"
    human_db_path = "all-results/human_accumulated_database.json"

    # 🎯 OFFICIAL 2025 MITRE CWE TOP 25 BASELINE ARRAY
    CWE_TOP_25 = [
        'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
        'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
        'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
        'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
    ]

    # Load AI dataset records
    ai_data = []
    if os.path.exists(ai_db_path):
        with open(ai_db_path, "r", encoding="utf-8") as f:
            ai_data = json.load(f)

    # Load Human dataset records
    human_data = []
    if os.path.exists(human_db_path):
        with open(human_db_path, "r", encoding="utf-8") as f:
            human_data = json.load(f)

    # --- AI CALCULATIONS ---
    total_ai_prs = len(ai_data)
    vulnerable_ai_prs = sum(1 for x in ai_data if x.get('has_issues_bool', False))
    total_ai_loc = sum(int(x.get('loc', 0)) for x in ai_data)
    
    total_ai_issues = 0
    for x in ai_data:
        tokens = str(x.get('issues_files', '0')).strip().split()
        if tokens and tokens[0].isdigit():
            total_ai_issues += int(tokens[0])
            
    ai_density = round(total_ai_issues / total_ai_loc, 6) if total_ai_loc > 0 else 0.0
    ai_avg_defect_rate = round(total_ai_issues / total_ai_prs, 2) if total_ai_prs > 0 else 0.0

    ai_high = sum(int(x.get('h', 0)) for x in ai_data)
    ai_medium = sum(int(x.get('m', 0)) for x in ai_data)
    ai_low = sum(int(x.get('l', 0)) for x in ai_data)
    
    ai_open = sum(1 for x in ai_data if "Open" in str(x.get('status', '')))
    ai_merged = sum(1 for x in ai_data if "Merged" in str(x.get('status', '')))
    ai_closed = sum(1 for x in ai_data if "Closed" in str(x.get('status', '')))

    ai_global_merge_rate = round((ai_merged / total_ai_prs) * 100, 2) if total_ai_prs > 0 else 0.0

    # 🔬 AI Advanced Analytical Metrics
    ai_critical_ratio = round((ai_high / total_ai_issues) * 100, 2) if total_ai_issues > 0 else 0.0
    ai_defect_concentration = round(total_ai_issues / vulnerable_ai_prs, 2) if vulnerable_ai_prs > 0 else 0.0
    
    ai_vuln_merged = sum(1 for x in ai_data if x.get('has_issues_bool', False) and "Merged" in str(x.get('status', '')))
    ai_dismissal_rate = round((ai_vuln_merged / vulnerable_ai_prs) * 100, 2) if vulnerable_ai_prs > 0 else 0.0

    # 🔬 Un-Nested AI Multi-Pass Data Synthesis Engine
    ai_cwe_by_severity = {"High": {}, "Medium": {}, "Low": {}}
    ai_all_unique = set()

    for x in ai_data:
        findings = x.get('findings_details', [])
        for bug in findings:
            vuln_title = bug.get('vulnerability', 'Security Weakness Discovered').strip()
            raw_cwes = bug.get('cwes', [])
            
            finding_cwe_list = [str(c).strip().upper() for c in raw_cwes if str(c).strip() and str(c).strip().upper() != 'NONE']
            
            for cwe in finding_cwe_list:
                ai_all_unique.add(cwe)
                target_sev = "High" if cwe in CWE_TOP_25 else "Medium"
                
                if cwe not in ai_cwe_by_severity[target_sev]:
                    ai_cwe_by_severity[target_sev][cwe] = set()
                ai_cwe_by_severity[target_sev][cwe].add(vuln_title)

    ai_cwe_breadth = len(ai_all_unique)
    # --- HUMAN CALCULATIONS ---
    total_human_prs = len(human_data)
    vulnerable_human_prs = sum(1 for x in human_data if x.get('has_issues_bool', False))
    total_human_loc = sum(int(x.get('loc', 0)) for x in human_data)
    
    total_human_issues = 0
    for x in human_data:
        tokens = str(x.get('issues_files', '0')).strip().split()
        if tokens and tokens.isdigit():
            total_human_issues += int(tokens)
            
    human_density = round(total_human_issues / total_human_loc, 6) if total_human_loc > 0 else 0.0
    human_avg_defect_rate = round(total_human_issues / total_human_prs, 2) if total_human_prs > 0 else 0.0

    human_high = sum(int(x.get('h', 0)) for x in human_data)
    human_medium = sum(int(x.get('m', 0)) for x in human_data)
    human_low = sum(int(x.get('l', 0)) for x in human_data)
    
    human_open = sum(1 for x in human_data if "Open" in str(x.get('status', '')))
    human_merged = sum(1 for x in human_data if "Merged" in str(x.get('status', '')))
    human_closed = sum(1 for x in human_data if "Closed" in str(x.get('status', '')))

    human_global_merge_rate = round((human_merged / total_human_prs) * 100, 2) if total_human_prs > 0 else 0.0

    # 🔬 Human Advanced Analytical Metrics
    human_critical_ratio = round((human_high / total_human_issues) * 100, 2) if total_human_issues > 0 else 0.0
    human_defect_concentration = round(total_human_issues / vulnerable_human_prs, 2) if vulnerable_human_prs > 0 else 0.0
    
    human_vuln_merged = sum(1 for x in human_data if x.get('has_issues_bool', False) and "Merged" in str(x.get('status', '')))
    human_dismissal_rate = round((human_vuln_merged / vulnerable_human_prs) * 100, 2) if vulnerable_human_prs > 0 else 0.0

    # 🔬 Un-Nested Human Multi-Pass Data Synthesis Engine
    human_cwe_by_severity = {"High": {}, "Medium": {}, "Low": {}}
    human_all_unique = set()

    for x in human_data:
        findings = x.get('findings_details', [])
        for bug in findings:
            vuln_title = bug.get('vulnerability', 'Security Weakness Discovered').strip()
            raw_cwes = bug.get('cwes', [])
            
            finding_cwe_list = [str(c).strip().upper() for c in raw_cwes if str(c).strip() and str(c).strip().upper() != 'NONE']
            
            for cwe in finding_cwe_list:
                human_all_unique.add(cwe)
                target_sev = "High" if cwe in CWE_TOP_25 else "Medium"
                
                if cwe not in human_cwe_by_severity[target_sev]:
                    human_cwe_by_severity[target_sev][cwe] = set()
                human_cwe_by_severity[target_sev][cwe].add(vuln_title)

    human_cwe_breadth = len(human_all_unique)
    # --- GENERATE NESTED HTML SUB-LISTS WITH 10% / 50% / 40% FORCED COLUMN WIDTHS ---
    import re
    
    CWE_TITLES = {
        'CWE-020': 'Improper Input Validation',
        'CWE-079': "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        'CWE-080': 'Improper Neutralization of Script-Related HTML Tags in a Web Page',
        'CWE-116': 'Improper Encoding or Sanitization of Input',
        'CWE-209': 'Generation of Error Message Containing Sensitive Information',
        'CWE-307': 'Improper Restriction of Excessive Authentication Attempts',
        'CWE-312': 'Cleartext Storage of Sensitive Information',
        'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
        'CWE-328': 'Use of Weak Hash',
        'CWE-359': 'Exposure of Private Personal Information ("Privacy Violation")',
        'CWE-400': 'Uncontrolled Resource Consumption',
        'CWE-497': 'Exposure of System Information to an Unauthorized Actor',
        'CWE-532': 'Insertion of Sensitive Information into Log File',
        'CWE-601': 'URL Redirection to Untrusted Site (\'Open Redirect\')',
        'CWE-770': 'Allocation of Resources Without Limits or Throttling'
    }

    ai_cwe_html_list = ""
    for sev_name, cwe_dict in ai_cwe_by_severity.items():
        if cwe_dict:
            if sev_name == "High":
                badge_style = "background-color: #ffeef0; color: #cf222e; border: 1px solid rgba(207, 34, 46, 0.4);"
            else:
                badge_style = "background-color: #fff8e1; color: #bf8700; border: 1px solid rgba(191, 135, 0, 0.4);"

            ai_cwe_html_list += f"""
            <div style='margin-top:14px; margin-bottom:6px; font-size:13px; font-weight:bold; color:#24292f;'>{sev_name} Severities:</div>
            <div style='border:1px solid #d0d7de; border-radius:6px; margin-bottom:16px; overflow:hidden; background:#ffffff;'>
                <table style='width:100%; border-collapse:collapse; text-align:left; font-size:12px; table-layout:fixed;'>
            """
            for code, desc_set in sorted(cwe_dict.items()):
                rule_badges = "".join([f"<span style='background:#f6f8fa; color:#57606a; border:1px solid #d0d7de; border-radius:3px; padding:3px 6px; margin:2px; font-family:monospace; font-size:11px; display:inline-block; white-space:nowrap;'>{r.strip()}</span>" for r in desc_set])
                
                title_string = CWE_TITLES.get(code, "Unclassified Architectural Weakness")
                
                ai_cwe_html_list += f"""
                <tr style='border-bottom:1px solid #d0d7de;'>
                    <!-- Column 1: Classification ID (Forced Width locked at 10%) -->
                    <td style='width:10%; padding:12px 10px; border-right:1px solid #d0d7de; vertical-align:middle; background:#ffffff; overflow:hidden;'>
                        <code style='{badge_style} padding:4px 6px; border-radius:4px; font-weight:bold; font-size:11px; font-family:monospace; display:inline-block; white-space:nowrap;'>{code}</code>
                    </td>
                    <!-- Column 2: MITRE Nomenclature (Forced Width locked at 50%) -->
                    <td style='width:50%; padding:12px 10px; border-right:1px solid #d0d7de; color:#24292f; font-weight:500; line-height:1.4; vertical-align:middle; background:#ffffff; word-wrap:break-word;'>
                        {title_string}
                    </td>
                    <!-- Column 3: Triggering Rules (Forced Width expanded locked at 40%) -->
                    <td style='width:40%; padding:12px 10px; text-align:right; vertical-align:middle; background:#ffffff;'>
                        <div style='display:flex; flex-wrap:wrap; justify-content:flex-end; gap:2px;'>{rule_badges}</div>
                    </td>
                </tr>"""
            ai_cwe_html_list += "</table></div>"
    if not ai_cwe_html_list:
        ai_cwe_html_list = "<div style='font-size:12px; color:#57606a;'>No CWE mappings registered.</div>"

    human_cwe_html_list = ""
    for sev_name, cwe_dict in human_cwe_by_severity.items():
        if cwe_dict:
            if sev_name == "High":
                badge_style = "background-color: #ffeef0; color: #cf222e; border: 1px solid rgba(207, 34, 46, 0.4);"
            else:
                badge_style = "background-color: #fff8e1; color: #bf8700; border: 1px solid rgba(191, 135, 0, 0.4);"

            human_cwe_html_list += f"""
            <div style='margin-top:14px; margin-bottom:6px; font-size:13px; font-weight:bold; color:#24292f;'>{sev_name} Severities:</div>
            <div style='border:1px solid #d0d7de; border-radius:6px; margin-bottom:16px; overflow:hidden; background:#ffffff;'>
                <table style='width:100%; border-collapse:collapse; text-align:left; font-size:12px; table-layout:fixed;'>
            """
            for code, desc_set in sorted(cwe_dict.items()):
                rule_badges = "".join([f"<span style='background:#f6f8fa; color:#57606a; border:1px solid #d0d7de; border-radius:3px; padding:3px 6px; margin:2px; font-family:monospace; font-size:11px; display:inline-block; white-space:nowrap;'>{r.strip()}</span>" for r in desc_set])
                
                title_string = CWE_TITLES.get(code, "Unclassified Architectural Weakness")
                
                human_cwe_html_list += f"""
                <tr style='border-bottom:1px solid #d0d7de;'>
                    <!-- Column 1: Classification ID (Forced Width locked at 10%) -->
                    <td style='width:10%; padding:12px 10px; border-right:1px solid #d0d7de; vertical-align:middle; background:#ffffff; overflow:hidden;'>
                        <code style='{badge_style} padding:4px 6px; border-radius:4px; font-weight:bold; font-size:11px; font-family:monospace; display:inline-block; white-space:nowrap;'>{code}</code>
                    </td>
                    <!-- Column 2: MITRE Nomenclature (Forced Width locked at 50%) -->
                    <td style='width:50%; padding:12px 10px; border-right:1px solid #d0d7de; color:#24292f; font-weight:500; line-height:1.4; vertical-align:middle; background:#ffffff; word-wrap:break-word;'>
                        {title_string}
                    </td>
                    <!-- Column 3: Triggering Rules (Forced Width expanded locked at 40%) -->
                    <td style='width:40%; padding:12px 10px; text-align:right; vertical-align:middle; background:#ffffff;'>
                        <div style='display:flex; flex-wrap:wrap; justify-content:flex-end; gap:2px;'>{rule_badges}</div>
                    </td>
                </tr>"""
            human_cwe_html_list += "</table></div>"
    if not human_cwe_html_list:
        human_cwe_html_list = "<div style='font-size:12px; color:#57606a;'>No CWE mappings registered.</div>"
    # --- COMPILE HTML GRID TEMPLATE ---
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Thesis Empirical Analysis: AI vs Human Code Security</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f6f8fa; padding: 40px; color: #24292f; }}
        h1 {{ border-bottom: 1px solid #d0d7de; padding-bottom: 10px; margin-bottom: 30px; }}
        .comparison-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 40px; }}
        .card {{ background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .ai-card {{ border-top: 6px solid #0969da; }}
        .human-card {{ border-top: 6px solid #2da44e; }}
        h3 {{ margin-top: 0; font-size: 20px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #eaecef; padding-bottom: 8px; }}
        h4 {{ margin-top: 20px; margin-bottom: 5px; color: #57606a; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px dashed #eaecef; padding-bottom: 3px; }}
        ul {{ list-style: none; padding: 0; margin: 0 0 15px 0; }}
        li {{ padding: 10px 0; border-bottom: 1px solid #f6f8fa; font-size: 15px; display: flex; justify-content: space-between; }}
        li:last-child {{ border-bottom: none; }}
        .metric-value {{ font-weight: bold; font-size: 16px; }}
        .badge-vuln-flag {{ padding: 4px 10px; font-size: 12px; font-weight: 600; border-radius: 2em; color: #fff; background-color: #cf222e; }}
        .severity-track {{ display: flex; gap: 10px; margin-top: 5px; background: #fafafa; padding: 10px; border-radius: 6px; border: 1px dashed #d0d7de; }}
        .severity-item {{ flex: 1; text-align: center; font-size: 13px; font-weight: bold; }}
        .sev-h {{ color: #cf222e; }}
        .sev-m {{ color: #d4a724; }}
        .sev-l {{ color: #0969da; }}
        .summary-box {{ background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 24px; margin-top: 30px; text-align: center; }}
    </style>
</head>
<body>
    <h1>📊 Thesis Empirical Analysis: AI vs Human Code Security Summary</h1>
    <div class="comparison-grid">
        <!-- 🤖 AI-Generated Pull Requests Card -->
        <div class="card ai-card">
            <h3>🤖 AI-Generated Pull Requests</h3>
            
            <h4>📈 General Size & Metrics</h4>
            <ul>
                <li><span>Total Pull Requests Audited:</span> <span class="metric-value">{total_ai_prs}</span></li>
                <li><span>Total Lines of Code (LOC):</span> <span class="metric-value">{total_ai_loc:,} lines</span></li>
                <li><span>Vulnerable PR Footprint:</span> <span class="badge-vuln-flag">{vulnerable_ai_prs} PRs Flagged</span></li>
            </ul>

            <h4>🔄 PR Lifecycle Status Distribution</h4>
            <ul>
                <li><span>🟢 Active Open Branches:</span> <span class="metric-value">{ai_open}</span></li>
                <li><span>🟣 Merged Production Code:</span> <span class="metric-value">{ai_merged}</span></li>
                <li><span>🔴 Closed / Rejected Code:</span> <span class="metric-value">{ai_closed}</span></li>
            </ul>

            <h4>⚖️ Security Alert Breakdown</h4>
            <ul>
                <li><span>Total Security Deficiencies Found:</span> <span class="metric-value">{total_ai_issues} defects</span></li>
                <li><span>CWE Defect Density (Issues/LOC):</span> <span class="metric-value">{ai_density:.6f}</span></li>
                <li><span>Average Defect Rate (Total Defects / Total PRs):</span> <span class="metric-value">{ai_avg_defect_rate} defects/PR</span></li>
                <li><span>Global Merged Rate (Merged PRs / Total PRs):</span> <span class="metric-value">{ai_global_merge_rate}%</span></li>
            </ul>
            <div class="severity-track">
                <div class="severity-item sev-h">🔴 High: {ai_high}</div>
                <div class="severity-item sev-m">🟡 Medium: {ai_medium}</div>
                <div class="severity-item sev-l">🔵 Low: {ai_low}</div>
            </div>

            <h4>🧠 Advanced Research Metrics</h4>
            <ul>
                <li><span>High-Severity Critical Ratio (High Defects / Total Defects):</span> <span class="metric-value">{ai_critical_ratio}%</span></li>
                <li><span>Defect Concentration Factor (Total Defects / Vulnerable PRs):</span> <span class="metric-value">{ai_defect_concentration} bugs/Vulnerable PR</span></li>
                <li><span>Alert Dismissal Rate (Vulnerable Merged PRs / Total Vulnerable PRs):</span> <span class="metric-value">{ai_dismissal_rate}%</span></li>
                <li><span>Unique CWE Landscape Breadth (Count of Unique CWE IDs):</span> <span class="metric-value">{ai_cwe_breadth} types</span></li>
            </ul>

            <h4>🔬 Security Vulnerability Analysis</h4>
            <div style="margin-top: 8px;">
                {ai_cwe_html_list}
            </div>
        </div>
        <!-- 👨‍💻 Human Pull Requests Card -->
        <div class="card human-card">
            <h3>👨‍💻 Human Pull Requests</h3>
            
            <h4>📈 General Size & Metrics</h4>
            <ul>
                <li><span>Total Pull Requests Audited:</span> <span class="metric-value">{total_human_prs}</span></li>
                <li><span>Total Lines of Code (LOC):</span> <span class="metric-value">{total_human_loc:,} lines</span></li>
                <li><span>Vulnerable PR Footprint:</span> <span class="badge-vuln-flag">{vulnerable_human_prs} PRs Flagged</span></li>
            </ul>

            <h4>🔄 PR Lifecycle Status Distribution</h4>
            <ul>
                <li><span>🟢 Active Open Branches:</span> <span class="metric-value">{human_open}</span></li>
                <li><span>🟣 Merged Production Code:</span> <span class="metric-value">{human_merged}</span></li>
                <li><span>🔴 Closed / Rejected Code:</span> <span class="metric-value">{human_closed}</span></li>
            </ul>

            <h4>⚖️ Security Alert Breakdown</h4>
            <ul>
                <li><span>Total Security Deficiencies Found:</span> <span class="metric-value">{total_human_issues} defects</span></li>
                <li><span>CWE Defect Density (Issues/LOC):</span> <span class="metric-value">{human_density:.6f}</span></li>
                <li><span>Average Defect Rate (Total Defects / Total PRs):</span> <span class="metric-value">{human_avg_defect_rate} defects/PR</span></li>
                <li><span>Global Merged Rate (Merged PRs / Total PRs):</span> <span class="metric-value">{human_global_merge_rate}%</span></li>
            </ul>
            <div class="severity-track">
                <div class="severity-item sev-h">🔴 High: {human_high}</div>
                <div class="severity-item sev-m">🟡 Medium: {human_medium}</div>
                <div class="severity-item sev-l">🔵 Low: {human_low}</div>
            </div>

            <h4>🧠 Advanced Research Metrics</h4>
            <ul>
                <li><span>High-Severity Critical Ratio (High Defects / Total Defects):</span> <span class="metric-value">{human_critical_ratio}%</span></li>
                <li><span>Defect Concentration Factor (Total Defects / Vulnerable PRs):</span> <span class="metric-value">{human_defect_concentration} bugs/Vulnerable PR</span></li>
                <li><span>Alert Dismissal Rate (Vulnerable Merged PRs / Total Vulnerable PRs):</span> <span class="metric-value">{human_dismissal_rate}%</span></li>
                <li><span>Unique CWE Landscape Breadth (Count of Unique CWE IDs):</span> <span class="metric-value">{human_cwe_breadth} types</span></li>
            </ul>

            <h4>🔬 Security Vulnerability Analysis</h4>
            <div style="margin-top: 8px;">
                {human_cwe_html_list}
            </div>
        </div>
    </div>

    <div class="summary-box">
        <h3>🔍 Quick Thesis Observation Note</h3>
        <p>AI Defect Density is <strong>{ai_density:.6f}</strong> vs Human Defect Density of <strong>{human_density:.6f}</strong>.</p>
        <p>This side-by-side distribution maps out your entire security analysis framework cleanly for your research defense slides.</p>
    </div>

</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as out:
        out.write(html_content)
    print(f"✨ SUCCESS: Consolidated thesis evaluation matrix compiled at: {output_path}")

if __name__ == "__main__":
    main()
