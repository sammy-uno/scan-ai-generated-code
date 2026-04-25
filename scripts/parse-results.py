import json
import os

def main():
    # The action often creates a directory if 'output' is specified
    base_path = 'results.sarif'
    sarif_file = None

    if os.path.isdir(base_path):
        # Look for the first .sarif file inside the directory
        for root, dirs, files in os.walk(base_path):
            for file in files:
                if file.endswith('.sarif'):
                    sarif_file = os.path.join(root, file)
                    break
    elif os.path.isfile(base_path):
        sarif_file = base_path

    if not sarif_file:
        print(f"No SARIF file found in {base_path}")
        return

    print(f"Parsing results from: {sarif_file}")
    with open(sarif_file, 'r') as f:
        data = json.load(f)

    # Get the list of results
    runs = data.get('runs', [])
    results = runs[0].get('results', []) if runs else []
    
    summary_md = f"\n### 📊 Found {len(results)} Vulnerabilities\n"
    summary_md += "| Severity | Vulnerability | Description |\n"
    summary_md += "| :--- | :--- | :--- |\n"

    # Map severity levels to emojis
    # SARIF levels: error, warning, note, or none
    severity_icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low", "none": "⚪ Info"}

    for res in results:
        rule_id = res.get('ruleId', 'N/A')
        # Extract the message text
        msg_text = res.get('message', {}).get('text', 'No description')
        # Clean up message (take first line only for the table)
        short_msg = msg_text.split('\n')[0]
        
        level = res.get('level', 'warning')
        icon = severity_icons.get(level, "🟡 Medium")
        
        summary_md += f"| {icon} | `{rule_id}` | {short_msg} |\n"

    # Append to the GitHub Summary file
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary_file:
        with open(summary_file, 'a') as f:
            f.write(summary_md)
    else:
        print(summary_md)

if __name__ == "__main__":
    main()
