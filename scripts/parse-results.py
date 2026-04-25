import json
import os

def main():
    base_path = 'results.sarif'
    sarif_file = None

    if os.path.isdir(base_path):
        for root, dirs, files in os.walk(base_path):
            for file in files:
                if file.endswith('.sarif'):
                    sarif_file = os.path.join(root, file)
                    break
    elif os.path.isfile(base_path):
        sarif_file = base_path

    if not sarif_file:
        print("No SARIF file found.")
        return

    with open(sarif_file, 'r') as f:
        data = json.load(f)

    runs = data.get('runs', [])
    results = runs[0].get('results', []) if runs else []
    
    summary_md = f"\n### 🛡️ AI-Generated Code Analysis: {len(results)} Issues Found\n"
    if not results:
        summary_md += "_No security issues detected in the modified files._\n"
    else:
        summary_md += "| Severity | Vulnerability | File | Description |\n"
        summary_md += "| :--- | :--- | :--- | :--- |\n"
        
        icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}

        for res in results:
            rule_id = res.get('ruleId', 'N/A')
            msg = res.get('message', {}).get('text', 'No description').split('\n')[0]
            level = res.get('level', 'warning')
            icon = icons.get(level, "🟡 Medium")
            
            # Extract file path
            locs = res.get('locations', [{}])
            path = locs[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'Unknown')
            
            summary_md += f"| {icon} | `{rule_id}` | `{path}` | {msg} |\n"

    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary_md)

if __name__ == "__main__":
    main()
