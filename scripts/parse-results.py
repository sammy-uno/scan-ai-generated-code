import json
import os

def main():
    sarif_file = 'results.sarif'
    if not os.path.exists(sarif_file):
        print("No results file found.")
        return

    with open(sarif_file, 'r') as f:
        data = json.load(f)

    # Get the list of results
    results = data.get('runs', [{}])[0].get('results', [])
    
    summary_md = f"\n### 📊 Found {len(results)} Vulnerabilities\n"
    summary_md += "| Severity | Vulnerability | Description |\n"
    summary_md += "| :--- | :--- | :--- |\n"

    # Map severity levels to emojis
    severity_icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}

    for res in results:
        rule_id = res.get('ruleId', 'N/A')
        msg = res.get('message', {}).get('text', 'No description').split('\n')[0]
        # CodeQL SARIF severity is usually in the rule metadata or result level
        # This is a simplified extraction
        level = res.get('level', 'warning')
        icon = severity_icons.get(level, "🟡 Medium")
        
        summary_md += f"| {icon} | `{rule_id}` | {msg} |\n"

    # Append to the GitHub Summary file
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
        f.write(summary_md)

if __name__ == "__main__":
    main()
