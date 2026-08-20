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

    # Calculate global statistical distributions
    total_ai_prs = len(ai_data)
    vulnerable_ai_prs = sum(1 for x in ai_data if x.get('has_issues_bool', False))
    total_ai_loc = sum(int(x.get('loc', 0)) for x in ai_data)
    total_ai_issues = sum(int(str(x.get('issues_files', '0')).split()[0]) for x in ai_data if x.get('issues_files'))
    ai_density = round(total_ai_issues / total_ai_loc, 6) if total_ai_loc > 0 else 0.0

    total_human_prs = len(human_data)
    vulnerable_human_prs = sum(1 for x in human_data if x.get('has_issues_bool', False))
    total_human_loc = sum(int(x.get('loc', 0)) for x in human_data)
    total_human_issues = sum(int(str(x.get('issues_files', '0')).split()[0]) for x in human_data if x.get('issues_files'))
    human_density = round(total_human_issues / total_human_loc, 6) if total_human_loc > 0 else 0.0

    # Compile the side-by-side frontend structure
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
        h3 {{ margin-top: 0; font-size: 20px; display: flex; align-items: center; gap: 8px; }}
        ul {{ list-style: none; padding: 0; margin: 0; }}
        li {{ padding: 12px 0; border-bottom: 1px solid #eaecef; font-size: 15px; display: flex; justify-content: space-between; }}
        li:last-child {{ border-bottom: none; }}
        .metric-value {{ font-weight: bold; font-size: 16px; }}
        .badge {{ padding: 4px 10px; font-size: 12px; font-weight: 600; border-radius: 2em; color: #fff; }}
        .badge-ai {{ background-color: #0969da; }}
        .badge-human {{ background-color: #2da44e; }}
        .summary-box {{ background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 24px; margin-top: 30px; text-align: center; }}
        .delta-highlight {{ color: #cf222e; font-weight: bold; }}
    </style>
</head>
<body>

    <h1>📊 Thesis Empirical Analysis: AI vs Human Code Security Summary</h1>
    
    <div class="comparison-grid">
        <!-- AI Automated Dataset Tracker Card -->
        <div class="card ai-card">
            <h3>🤖 AI-Generated Code Dataset (AIDev)</h3>
            <ul>
                <li><span>Total Pull Requests Audited:</span> <span class="metric-value">{total_ai_prs}</span></li>
                <li><span>Total Lines of Code (LOC):</span> <span class="metric-value">{total_ai_loc:,} lines</span></li>
                <li><span>Vulnerable PR Footprint:</span> <span class="badge badge-ai">{vulnerable_ai_prs} PRs Flagged</span></li>
                <li><span>Total Security Deficiencies Found:</span> <span class="metric-value">{total_ai_issues} defects</span></li>
                <li><span>CWE Defect Density (Issues/LOC):</span> <span class="metric-value">{ai_density:.6f}</span></li>
            </ul>
        </div>

        <!-- Human Auditor Baseline Tracker Card -->
        <div class="card human-card">
            <h3>👨‍💻 Human-Generated Code Baseline</h3>
            <ul>
                <li><span>Total Pull Requests Audited:</span> <span class="metric-value">{total_human_prs}</span></li>
                <li><span>Total Lines of Code (LOC):</span> <span class="metric-value">{total_human_loc:,} lines</span></li>
                <li><span>Vulnerable PR Footprint:</span> <span class="badge badge-human">{vulnerable_human_prs} PRs Flagged</span></li>
                <li><span>Total Security Deficiencies Found:</span> <span class="metric-value">{total_human_issues} defects</span></li>
                <li><span>CWE Defect Density (Issues/LOC):</span> <span class="metric-value">{human_density:.6f}</span></li>
            </ul>
        </div>
    </div>

    <div class="summary-box">
        <h3>🔍 Quick Thesis Observation Note</h3>
        <p>AI Defect Density is <strong>{ai_density:.6f}</strong> vs Human Defect Density of <strong>{human_density:.6f}</strong>.</p>
        <p>This empirical distribution provides the direct data foundation needed to quantify security deltas for your research chapters.</p>
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
