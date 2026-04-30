import json, os, sys

def main():
    if not os.path.exists("results.sarif"): return
    with open("results.sarif", 'r') as f:
        data = json.load(f)

    results = data.get('runs', [{}])[0].get('results', [])
    summary_md = f"\n### 🛡️ Analysis Details: {len(results)} Issues Found\n"
    
    if results:
        summary_md += "| Severity | Vulnerability | File:Line | Description |\n| :--- | :--- | :--- | :--- |\n"
        icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}
        for res in results:
            phys = res.get('locations', [{}])[0].get('physicalLocation', {})
            path = phys.get('artifactLocation', {}).get('uri', 'Unknown')
            line = phys.get('region', {}).get('startLine', '?')
            summary_md += f"| {icons.get(res.get('level'), '🟡')} | `{res.get('ruleId')}` | `{path}:{line}` | {res.get('message', {}).get('text', '').splitlines()[0]} |\n"

    with open(os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md'), 'a') as f:
        f.write(summary_md)

if __name__ == "__main__": main()
