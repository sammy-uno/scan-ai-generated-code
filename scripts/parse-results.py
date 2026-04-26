import json
import os

def main():
    sarif_file = 'results.sarif'
    if not os.path.exists(sarif_file):
        return

    with open(sarif_file, 'r') as f:
        data = json.load(f)

    runs = data.get('runs', [])
    results = runs[0].get('results', []) if runs else []
    
    summary_md = f"\n### 🛡️ Analysis Results: {len(results)} Issues Found\n"
    if not results:
        summary_md += "_No security issues detected in modified files._\n"
    else:
        summary_md += "| Severity | Vulnerability | File | Description |\n| :--- | :--- | :--- | :--- |\n"
        icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}

        for res in results:
            rule_id = res.get('ruleId', 'N/A')
            msg = res.get('message', {}).get('text', 'No description').split('\n')[0]
            icon = icons.get(res.get('level', 'warning'), "🟡 Medium")
            locs = res.get('locations', [{}])
            path = locs[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'Unknown')
            summary_md += f"| {icon} | `{rule_id}` | `{path}` | {msg} |\n"

    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary_md)

if __name__ == "__main__":
    main()
