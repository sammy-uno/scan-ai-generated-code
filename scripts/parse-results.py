import json, os, sys

def main():
    sarif_path = "results.sarif"
    if not os.path.exists(sarif_path):
        return
        
    try:
        with open(sarif_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return

    # Safeguard against empty SARIF runs
    runs = data.get('runs', [])
    if not runs:
        return
        
    results = runs[0].get('results', [])
    summary_md = f"\n### 🛡️ Analysis Details: {len(results)} Issues Found\n"
    
    if results:
        summary_md += "| Severity | Vulnerability | File:Line | Description |\n| :--- | :--- | :--- | :--- |\n"
        icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}
        for res in results:
            locs = res.get('locations', [{}])[0].get('physicalLocation', {})
            path = locs.get('artifactLocation', {}).get('uri', 'Unknown')
            line = locs.get('region', {}).get('startLine', '?')
            level = res.get('level', 'warning')
            # Extract first line of description only
            msg = res.get('message', {}).get('text', 'No description').split('\n')[0]
            summary_md += f"| {icons.get(level, '🟡')} | `{res.get('ruleId')}` | `{path}:{line}` | {msg} |\n"

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'a') as f:
        f.write(summary_md)

if __name__ == "__main__":
    main()
