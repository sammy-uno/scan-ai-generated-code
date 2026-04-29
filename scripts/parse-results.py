import json
import os
import glob
import sys

def main():
    # Find all .sarif files in the current directory
    sarif_files = glob.glob("*.sarif")
    if not sarif_files:
        print("DEBUG: No SARIF files found in current directory.", file=sys.stderr)
        return

    all_results = []
    icons = {"error": "🔴 High", "warning": "🟡 Medium", "note": "🔵 Low"}

    for sarif_file in sarif_files:
        print(f"Parsing: {sarif_file}")
        try:
            with open(sarif_file, 'r') as f:
                data = json.load(f)
            
            runs = data.get('runs', [])
            for run in runs:
                results = run.get('results', [])
                for res in results:
                    rule_id = res.get('ruleId', 'N/A')
                    msg = res.get('message', {}).get('text', 'No description').split('\n')[0]
                    level = res.get('level', 'warning')
                    icon = icons.get(level, "🟡 Medium")
                    
                    locs = res.get('locations', [{}])
                    path = locs[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'Unknown')
                    
                    all_results.append(f"| {icon} | `{rule_id}` | `{path}` | {msg} |")
        except Exception as e:
            print(f"Error parsing {sarif_file}: {e}", file=sys.stderr)

    # Build the final Markdown string
    summary_md = f"\n### 🛡️ Analysis Results for {os.environ.get('GITHUB_JOB', 'Scan')}\n"
    if not all_results:
        summary_md += "_No security issues detected in modified files._\n"
    else:
        summary_md += f"**Found {len(all_results)} potential issues.**\n\n"
        summary_md += "| Severity | Vulnerability | File | Description |\n| :--- | :--- | :--- | :--- |\n"
        summary_md += "\n".join(all_results) + "\n"

    # Write to the GitHub Step Summary
    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary_md)
    else:
        print(summary_md)

if __name__ == "__main__":
    main()
