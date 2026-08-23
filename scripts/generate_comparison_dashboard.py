import os
import json

def main():
    output_path = "docs/THESIS_COMPARATIVE_ANALYSIS.html"
    ai_db_path = "all-results/accumulated_database.json"
    human_db_path = "all-results/human_accumulated_database.json"

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
        val = str(x.get('issues_files', '0')).strip().split()
        if val and val[0].isdigit():
            total_ai_issues += int(val[0])
            
    ai_density = round(total_ai_issues / total_ai_loc, 6) if total_ai_loc > 0 else 0.0

    ai_high = sum(int(x.get('h', 0)) for x in ai_data)
    ai_medium = sum(int(x.get('m', 0)) for x in ai_data)
    ai_low = sum(int(x.get('l', 0)) for x in ai_data)
    
    ai_open = sum(1 for x in ai_data if "Open" in str(x.get('status', '')))
    ai_merged = sum(1 for x in ai_data if "Merged" in str(x.get('status', '')))
    ai_closed = sum(1 for x in ai_data if "Closed" in str(x.get('status', '')))

    # 🔬 AI Advanced Analytical Metrics
    ai_critical_ratio = round((ai_high / total_ai_issues) * 100, 2) if total_ai_issues > 0 else 0.0
    ai_defect_concentration = round(total_ai_issues / vulnerable_ai_prs, 2) if vulnerable_ai_prs > 0 else 0.0
    
    ai_vuln_merged = sum(1 for x in ai_data if x.get('has_issues_bool', False) and "Merged" in str(x.get('status', '')))
    ai_dismissal_rate = round((ai_vuln_merged / vulnerable_ai_prs) * 100, 2) if vulnerable_ai_prs > 0 else 0.0

    ai_unique_cwes = set()
    for x in ai_data:
        cwes = x.get('cwes', 'None')
        if cwes and cwes != 'None':
            for cwe in str(cwes).split(','):
                cwe_clean = cwe.strip()
                if cwe_clean:
                    ai_unique_cwes.add(cwe_clean)
    ai_cwe_breadth = len(ai_unique_cwes)
    # --- HUMAN CALCULATIONS ---
    total_human_prs = len(human_data)
    vulnerable_human_prs = sum(1 for x in human_data if x.get('has_issues_bool', False))
    total_human_loc = sum(int(x.get('loc', 0)) for x in human_data)
    
    total_human_issues = 0
    for x in human_data:
        val = str(x.get('issues_files', '0')).strip().split()
        if val and val.isdigit():
            total_human_issues += int(val)
            
    human_density = round(total_human_issues / total_human_loc, 6) if total_human_loc > 0 else 0.0

    human_high = sum(int(x.get('h', 0)) for x in human_data)
    human_medium = sum(int(x.get('m', 0)) for x in human_data)
    human_low = sum(int(x.get('l', 0)) for x in human_data)
    
    human_open = sum(1 for x in human_data if "Open" in str(x.get('status', '')))
    human_merged = sum(1 for x in human_data if "Merged" in str(x.get('status', '')))
    human_closed = sum(1 for x in human_data if "Closed" in str(x.get('status', '')))

    # 🔬 Human Advanced Analytical Metrics
    human_critical_ratio = round((human_high / total_human_issues) * 100, 2) if total_human_issues > 0 else 0.0
    human_defect_concentration = round(total_human_issues / vulnerable_human_prs, 2) if vulnerable_human_prs > 0 else 0.0
    
    human_vuln_merged = sum(1 for x in human_data if x.get('has_issues_bool', False) and "Merged" in str(x.get('status', '')))
    human_dismissal_rate = round((human_vuln_merged / vulnerable_human_prs) * 100, 2) if vulnerable_human_prs > 0 else 0.0

    human_unique_cwes = set()
    for x in human_data:
        cwes = x.get('cwes', 'None')
        if cwes and cwes != 'None':
            for cwe in str(cwes).split(','):
                cwe_clean = cwe.strip()
                if cwe_clean:
                    human_unique_cwes.add(cwe_clean)
    human_cwe_breadth = len(human_unique_cwes)

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

            <h4>⚖️ Security Alert Breakdown</h4>
            <ul>
                <li><span>Total Security Deficiencies Found:</span> <span class="metric-value">{total_ai_issues} defects</span></li>
                <li><span>CWE Defect Density (Issues/LOC):</span> <span class="metric-value">{ai_density:.6f}</span></li>
            </ul>
            <div class="severity-track">
                <div class="severity-item sev-h">🔴 High: {ai_high}</div>
                <div class="severity-item sev-m">🟡 Medium: {ai_medium}</div>
                <div class="severity-item sev-l">🔵 Low: {ai_low}</div>
            </div>

            <h4>🧠 Advanced Research Metrics</h4>
            <ul>
                <li><span>High-Severity Critical Ratio:</span> <span class="metric-value">{ai_critical_ratio}%</span></li>
                <li><span>Defect Concentration Factor:</span> <span class="metric-value">{ai_defect_concentration} bugs/PR</span></li>
                <li><span>Alert Dismissal Rate (Merged anyway):</span> <span class="metric-value">{ai_dismissal_rate}%</span></li>
                <li><span>Unique CWE Landscape Breadth:</span> <span class="metric-value">{ai_cwe_breadth} types</span></li>
            </ul>

            <h4>🔄 PR Lifecycle Status Distribution</h4>
            <ul>
                <li><span>🟢 Active Open Branches:</span> <span class="metric-value">{ai_open}</span></li>
                <li><span>🟣 Merged Production Code:</span> <span class="metric-value">{ai_merged}</span></li>
                <li><span>🔴 Closed / Rejected Code:</span> <span class="metric-value">{ai_closed}</span></li>
            </ul>
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

            <h4>⚖️ Security Alert Breakdown</h4>
            <ul>
                <li><span>Total Security Deficiencies Found:</span> <span class="metric-value">{total_human_issues} defects</span></li>
                <li><span>CWE Defect Density (Issues/LOC):</span> <span class="metric-value">{human_density:.6f}</span></li>
            </ul>
            <div class="severity-track">
                <div class="severity-item sev-h">🔴 High: {human_high}</div>
                <div class="severity-item sev-m">🟡 Medium: {human_medium}</div>
                <div class="severity-item sev-l">🔵 Low: {human_low}</div>
            </div>

            <h4>🧠 Advanced Research Metrics</h4>
            <ul>
                <li><span>High-Severity Critical Ratio:</span> <span class="metric-value">{human_critical_ratio}%</span></li>
                <li><span>Defect Concentration Factor:</span> <span class="metric-value">{human_defect_concentration} bugs/PR</span></li>
                <li><span>Alert Dismissal Rate (Merged anyway):</span> <span class="metric-value">{human_dismissal_rate}%</span></li>
                <li><span>Unique CWE Landscape Breadth:</span> <span class="metric-value">{human_cwe_breadth} types</span></li>
            </ul>

            <h4>🔄 PR Lifecycle Status Distribution</h4>
            <ul>
                <li><span>🟢 Active Open Branches:</span> <span class="metric-value">{human_open}</span></li>
                <li><span>🟣 Merged Production Code:</span> <span class="metric-value">{human_merged}</span></li>
                <li><span>🔴 Closed / Rejected Code:</span> <span class="metric-value">{human_closed}</span></li>
            </ul>
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
