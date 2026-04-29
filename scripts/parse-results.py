import json
import os
import glob
import sys

def main():
    sarif_file = "results.sarif"
    if not os.path.exists(sarif_file):
        return

    with open(sarif_file, 'r') as f:
        data = json.load(f)

    runs = data.get('runs', [])
    results = runs[0].get('results', []) if runs else []
    
    summary_md = f"\n### 🛡️ Analysis Details: {len(results)} Issues Found\n"
    if not results:
        summary_md += "_No security issues detected in modified files._\n"
    else:
        summary_md += "| Severity | Vulnerability | File:Line | Description |\n| :--- | :--- | :--- | :--- |\n"
        icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}

        for res in results:
            rule_id = res.get('ruleId', 'N/A')
            msg = res.get('message', {}).get('text', 'No description').split('\n')[0]
            level = res.get('level', 'warning')
            icon = icons.get(level, "🟡 Medium")
            
            # Extract Path and Line Number
            locs = res.get('locations', [{}])
            phys = locs[0].get('physicalLocation', {})
            path = phys.get('artifactLocation', {}).get('uri', 'Unknown')
            line = phys.get('region', {}).get('startLine', '?')
            
            summary_md += f"| {icon} | `{rule_id}` | `{path}:{line}` | {msg} |\n"

    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary_md)

if __name__ == "__main__":
    main()
